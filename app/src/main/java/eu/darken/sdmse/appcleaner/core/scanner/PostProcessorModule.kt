package eu.darken.sdmse.appcleaner.core.scanner

import dagger.Reusable
import eu.darken.sdmse.appcleaner.core.AppCleanerSettings
import eu.darken.sdmse.appcleaner.core.AppJunk
import eu.darken.sdmse.appcleaner.core.excludeNestedLookups
import eu.darken.sdmse.appcleaner.core.forensics.ExpendablesFilter
import eu.darken.sdmse.appcleaner.core.forensics.ExpendablesFilterIdentifier
import eu.darken.sdmse.appcleaner.core.forensics.filter.DefaultCachesPrivateFilter
import eu.darken.sdmse.appcleaner.core.forensics.filter.DefaultCachesPublicFilter
import eu.darken.sdmse.common.adb.AdbManager
import eu.darken.sdmse.common.adb.canUseAdbNow
import eu.darken.sdmse.common.datastore.value
import eu.darken.sdmse.common.debug.logging.Logging.Priority.INFO
import eu.darken.sdmse.common.debug.logging.Logging.Priority.VERBOSE
import eu.darken.sdmse.common.debug.logging.Logging.Priority.WARN
import eu.darken.sdmse.common.debug.logging.log
import eu.darken.sdmse.common.debug.logging.logTag
import eu.darken.sdmse.common.files.containsSegments
import eu.darken.sdmse.common.files.segs
import eu.darken.sdmse.common.flow.throttleLatest
import eu.darken.sdmse.common.hasApiLevel
import eu.darken.sdmse.common.pkgs.toPkgId
import eu.darken.sdmse.common.progress.Progress
import eu.darken.sdmse.common.root.RootManager
import eu.darken.sdmse.common.root.canUseRootNow
import eu.darken.sdmse.exclusion.core.ExclusionManager
import eu.darken.sdmse.exclusion.core.pathExclusions
import eu.darken.sdmse.main.core.SDMTool
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import javax.inject.Inject

@Reusable
class PostProcessorModule @Inject constructor(
    private val rootManager: RootManager,
    private val adbManager: AdbManager,
    private val exclusionManager: ExclusionManager,
    private val settings: AppCleanerSettings,
) : Progress.Host, Progress.Client {

    private val progressPub = MutableStateFlow<Progress.Data?>(null)
    override val progress: Flow<Progress.Data?> = progressPub.throttleLatest(250)

    override fun updateProgress(update: (Progress.Data?) -> Progress.Data?) {
        progressPub.value = update(progressPub.value)
    }

    /**
     * Parallelized post-processing.
     * CPU-intensive filtering is now distributed across threads.
     */
    suspend fun postProcess(apps: Collection<AppJunk>): Collection<AppJunk> {
        log(TAG) { "postProcess(${apps.size})" }

        val minCacheSize = settings.minCacheSizeBytes.value()
        log(TAG, INFO) { "Minimum cache size is $minCacheSize" }

        // Use CoroutineScope to process items in parallel chunks.
        // This is much faster than a standard .map chain for heavy regex/filtering logic.
        val processed = coroutineScope {
            apps.chunked(50).map { batch ->
                async(Dispatchers.Default) {
                    batch.mapNotNull { processSingleItem(it, minCacheSize) }
                }
            }.awaitAll().flatten()
        }

        log(TAG) { "After post processing: ${apps.size} reduced to ${processed.size}" }
        return processed
    }

    private suspend fun processSingleItem(app: AppJunk, minCacheSize: Long): AppJunk? {
        // Step 1: Check Aliases
        val aliased = checkAliasedItems(app)

        // Step 2: Check Exclusions (Can return null if fully excluded)
        val excluded = checkExclusions(aliased) ?: return null

        // Step 3: Hidden Modules & Size Check
        val result = checkForHiddenModules(excluded)

        // Final Size Filter
        return if (result.size >= minCacheSize && !result.isEmpty()) {
            result
        } else {
            if (result.size < minCacheSize) log(TAG, VERBOSE) { "Below minimum size: $result" }
            null
        }
    }

    private fun checkAliasedItems(before: AppJunk): AppJunk {
        if (before.expendables.isNullOrEmpty()) return before

        // Optimized: Don't recreate the map if no duplicates exist
        var hasChanges = false
        val newExpendables = before.expendables.mapValues { (_, value) ->
            val distinct = value.distinctBy { it.path }
            if (distinct.size != value.size) hasChanges = true
            distinct
        }.filter { it.value.isNotEmpty() }

        if (!hasChanges && newExpendables.size == before.expendables.size) return before

        if (hasChanges) {
             log(TAG) { "Duplicate/aliased items removed for ${before.pkg.packageName}" }
        }

        return before.copy(expendables = newExpendables)
    }

    private suspend fun checkExclusions(before: AppJunk): AppJunk? {
        if (before.expendables.isNullOrEmpty()) return before

        val useAdb = adbManager.canUseAdbNow()
        if (useAdb && adbManager.managerIds().contains(before.pkg.id)) {
            log(TAG, WARN) { "ADB is being used, excluding related packages." }
            return null
        }

        val useRoot = rootManager.canUseRootNow()
        val edgeCaseMap = mutableMapOf<ExpendablesFilterIdentifier, Collection<ExpendablesFilter.Match>>()

        // Edge case logic for non-root users using ADB
        if (!useRoot && useAdb) {
            val edgeCaseSegs = segs(before.pkg.id.name, "cache")
            val edgeCaseFilters = setOf(DefaultCachesPublicFilter::class, DefaultCachesPrivateFilter::class)
            
            before.expendables
                .filter { edgeCaseFilters.contains(it.key) }
                .forEach { (type, matches) ->
                    val edgeCases = matches.filter { it.path.segments.containsSegments(edgeCaseSegs) }
                    if (edgeCases.isNotEmpty()) edgeCaseMap[type] = edgeCases
                }
        }

        val exclusions = exclusionManager.pathExclusions(SDMTool.Type.APPCLEANER)

        // Filter exclusions
        val newExpendables = before.expendables.mapValues { (_, paths) ->
            exclusions.excludeNestedLookups(paths)
        }.toMutableMap()

        // Re-inject edge cases if necessary
        edgeCaseMap.forEach { (type, edges) ->
            if (edges.isNotEmpty()) {
                val existing = newExpendables[type] ?: emptySet()
                newExpendables[type] = (existing + edges).toSet()
                log(TAG, VERBOSE) { "Re-adding edge cases: $edges" }
            }
        }

        val after = before.copy(expendables = newExpendables)

        if (after.itemCount > before.itemCount) {
             // This is a critical logic error if it happens, so we keep the exception
            throw IllegalStateException("Item count after exclusions can't be greater than before!")
        }

        return after
    }

    private fun checkForHiddenModules(before: AppJunk): AppJunk {
        // Optimized: hasApiLevel check first (fastest), then Set lookup (Fast O(1))
        if (!hasApiLevel(29)) return before

        return if (HIDDEN_Q_PKGS.contains(before.pkg.id)) {
            bef
