package eu.darken.sdmse.appcleaner.core.forensics.filter

import dagger.Binds
import dagger.Module
import dagger.Reusable
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet
import eu.darken.sdmse.appcleaner.core.AppCleanerSettings
import eu.darken.sdmse.appcleaner.core.forensics.BaseExpendablesFilter
import eu.darken.sdmse.appcleaner.core.forensics.ExpendablesFilter
import eu.darken.sdmse.appcleaner.core.forensics.sieves.JsonAppSieve
import eu.darken.sdmse.common.areas.DataArea
import eu.darken.sdmse.common.datastore.value
import eu.darken.sdmse.common.debug.logging.log
import eu.darken.sdmse.common.debug.logging.logTag
import eu.darken.sdmse.common.files.APath
import eu.darken.sdmse.common.files.APathLookup
import eu.darken.sdmse.common.files.GatewaySwitch
import eu.darken.sdmse.common.files.Segments
import eu.darken.sdmse.common.pkgs.Pkg
import eu.darken.sdmse.common.storage.StorageEnvironment
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class BugReportingFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    environment: StorageEnvironment,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    // Optimized: Converted to HashSet for O(1) lookup
    private val cacheFolderPrefixes = environment.ourCacheDirs.map { it.name }.toHashSet()
    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_bug_reporting_files.json")
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        val size = pfpSegs.size
        if (size == 0) return null

        // 1. Check Default Cache Folder Exclusion
        // pkg/cache/file...
        if (size >= 2 && BLACKLIST_AREAS.contains(areaType)) {
            if (pkgId.name.equals(pfpSegs[0], ignoreCase = true) &&
                cacheFolderPrefixes.any { it.equals(pfpSegs[1], ignoreCase = true) }
            ) {
                return null
            }
        }

        // 2. Check Ignored Files (Fail Fast)
        if (IGNORED_FILES.contains(pfpSegs.last().lowercase())) {
            return null
        }

        // 3. Root Level Checks (Size >= 2)
        // basedir/filename
        if (size >= 2) {
            val segment1 = pfpSegs[1]
            val seg1Lower = segment1.lowercase()

            if (FILES.contains(seg1Lower)) {
                return target.toDeletionMatch()
            }

            if (LOGFILE_PATTERNS.any { it.matches(segment1) }) {
                return target.toDeletionMatch()
            }
        }

        // 4. Nested Checks (Size >= 3)
        // basedir/folder/file OR basedir/files/file
        if (size >= 3) {
            val segment1 = pfpSegs[1]
            val segment2 = pfpSegs[2]

            // Check: basedir/Logfiles/file
            if (FOLDERS.contains(segment1.lowercase())) {
                return target.toDeletionMatch()
            }

            // Check: basedir/files/log.txt
            if (FILES.contains(segment2.lowercase())) {
                return target.toDeletionMatch()
            }
        }

        // 5. Deep Nested Checks (Size >= 4)
        // package/files/.cache/file...
        if (size >= 4 &&
            (areaType == DataArea.Type.PUBLIC_DATA || areaType == DataArea.Type.PRIVATE_DATA)
        ) {
            if (SEGMENT_FILES.equals(pfpSegs[1], ignoreCase = true) &&
                FOLDERS.contains(pfpSegs[2].lowercase())
            ) {
                return target.toDeletionMatch()
            }
        }

        // 6. Sieve Check
        if (sieve.matches(pkgId, areaType, pfpSegs)) {
            return target.toDeletionMatch()
        }

        // 7. Crashlytics Checks (Optimized: No string allocation or parsing)
        // Path 1: pkg/files/.com.google.firebase.crashlytics.files.v2:pkgId/...
        if (size >= 3) {
            val segment1 = pfpSegs[1]
            if (SEGMENT_FILES.equals(segment1, ignoreCase = true)) {
                val segment2 = pfpSegs[2]
                
                // Check Path 1
                if (segment2.startsWith(CRASHLYTICS_V2_PREFIX, ignoreCase = true) &&
                    segment2.endsWith(pkgId.name, ignoreCase = true)
                ) {
                    return target.toDeletionMatch()
                }

                // Check Path 2: pkg/files/.crashlytics.v3/pkg/...
                if (size >= 4 &&
                    CRASHLYTICS_V3.equals(segment2, ignoreCase = true) &&
                    pkgId.name.equals(pfpSegs[3], ignoreCase = true)
                ) {
                    return target.toDeletionMatch()
                }
            }
        }

        return null
    }

    override suspend fun process(
        targets: Collection<ExpendablesFilter.Match>,
        allMatches: Collection<ExpendablesFilter.Match>
    ): ExpendablesFilter.ProcessResult {
        return deleteAll(
            targets.filterIsInstance<ExpendablesFilter.Match.Deletion>(),
            gatewaySwitch,
            allMatches
        )
    }

    @Reusable
    class Factory @Inject constructor(
        private val settings: AppCleanerSettings,
        private val filterProvider: Provider<BugReportingFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterBugreportingEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "BugReporting")
        private const val SEGMENT_FILES = "files"
        private const val CRASHLYTICS_V2_PREFIX = ".com.google.firebase.crashlytics.files.v2:"
        private const val CRASHLYTICS_V3 = ".crashlytics.v3"

        private val BLACKLIST_AREAS = setOf(
            DataArea.Type.PRIVATE_DATA,
            DataA
