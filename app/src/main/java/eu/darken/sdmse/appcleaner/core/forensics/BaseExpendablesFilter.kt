package eu.darken.sdmse.appcleaner.core.forensics

import eu.darken.sdmse.common.debug.Bugs
import eu.darken.sdmse.common.debug.logging.Logging.Priority.ERROR
import eu.darken.sdmse.common.debug.logging.Logging.Priority.INFO
import eu.darken.sdmse.common.debug.logging.Logging.Priority.VERBOSE
import eu.darken.sdmse.common.debug.logging.Logging.Priority.WARN
import eu.darken.sdmse.common.debug.logging.log
import eu.darken.sdmse.common.debug.logging.logTag
import eu.darken.sdmse.common.files.APathLookup
import eu.darken.sdmse.common.files.GatewaySwitch
import eu.darken.sdmse.common.files.PathException
import eu.darken.sdmse.common.files.delete
import eu.darken.sdmse.common.files.exists
import eu.darken.sdmse.common.files.filterDistinctRoots
import eu.darken.sdmse.common.files.isAncestorOf
import eu.darken.sdmse.common.flow.throttleLatest
import eu.darken.sdmse.common.progress.Progress
import eu.darken.sdmse.common.progress.increaseProgress
import eu.darken.sdmse.common.progress.updateProgressCount
import eu.darken.sdmse.common.progress.updateProgressPrimary
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow

abstract class BaseExpendablesFilter : ExpendablesFilter {

    private val progressPub = MutableStateFlow<Progress.Data?>(Progress.Data())
    override val progress: Flow<Progress.Data?> = progressPub.throttleLatest(250)

    override fun updateProgress(update: (Progress.Data?) -> Progress.Data?) {
        progressPub.value = update(progressPub.value)
    }

    suspend fun deleteAll(
        targets: Collection<ExpendablesFilter.Match.Deletion>,
        gatewaySwitch: GatewaySwitch,
        allMatches: Collection<ExpendablesFilter.Match>,
    ): ExpendablesFilter.ProcessResult {
        log(TAG, INFO) { "deleteAll(...) Processing ${targets.size} out of ${allMatches.size} matches" }
        updateProgressPrimary(eu.darken.sdmse.common.R.string.general_progress_preparing)

        val successful = mutableSetOf<ExpendablesFilter.Match>()
        val failed = mutableSetOf<Pair<ExpendablesFilter.Match, Exception>>()

        log(TAG, VERBOSE) { "Checking distinct roots..." }
        val distinctRoots = targets.map { it.lookup }.filterDistinctRoots()

        if (distinctRoots.size != targets.size) {
            log(TAG, INFO) { "${targets.size} match objects but only ${distinctRoots.size} distinct roots" }
            if (Bugs.isTrace) {
                targets
                    .filter { !distinctRoots.contains(it.lookup) }
                    .forEachIndexed { index, item -> log(TAG, INFO) { "Non distinct root #$index: $item" } }
            }
        }

        val targetsByLookup = targets.associateBy { it.lookup }

        val childrenByRoot = distinctRoots.associateWith { root ->
            val main = targetsByLookup[root]
            allMatches.filter { it != main && root.isAncestorOf(it.lookup) }
        }

        log(TAG) { "Got ${distinctRoots.size} distinct roots" }
        updateProgressCount(Progress.Count.Percent(distinctRoots.size))

        distinctRoots.forEach { targetRoot ->
            log(TAG) { "Processing root: $targetRoot" }
            updateProgressPrimary(targetRoot.userReadablePath)

            val main = targetsByLookup[targetRoot]!!
            val affected = childrenByRoot[targetRoot] ?: emptyList()

            if (Bugs.isTrace) {
                log(TAG) { "$main affects ${affected.size} other matches" }
                affected.forEach { log(TAG, VERBOSE) { "Affected: $it" } }
            }

            val deleteResult = attemptSafeDelete(targetRoot, gatewaySwitch)

            when (deleteResult) {
                is DeletionResult.Success -> {
                    successful.add(main)
                    successful.addAll(affected)
                    if (deleteResult.wasExisting) {
                        log(TAG) { "Main match deleted: $main" }
                        log(TAG) { "Main match and affected files deleted" }
                    } else {
                        log(TAG, WARN) { "Deletion failed as file no longer exists, okay..." }
                    }
                }
                is DeletionResult.Failure -> {
                    log(TAG, WARN) { "Deletion failed, file still exists" }
                    log(TAG, ERROR) { "Post-deletion-failure-exist check failed on $main\n ${deleteResult.error}" }
                    failed.add(main to deleteResult.error)

                    log(TAG, WARN) { "Main match failed to delete, checking what still exists" }
                    affected.forEach { subMatch ->
                        if (subMatch.lookup.exists(gatewaySwitch)) {
                            log(TAG, WARN) { "Sub match still exists: $subMatch" }
                        } else {
                            log(TAG, INFO) { "Sub match no longer exists: $subMatch" }
                            successful.add(subMatch)
                        }
                    }
                }
            }
            increaseProgress()
        }

        return ExpendablesFilter.ProcessResult(
            success = successful,
            failed = failed,
        )
    }

    private fun attemptSafeDelete(
        target: APathLookup<*>,
        gatewaySwitch: GatewaySwitch
    ): DeletionResult {
        return try {
            target.delete(gatewaySwitch, recursive = true)
            DeletionResult.Success(wasExisting = true)
        } catch (e: PathException) {
            try {
                if (target.exists(gatewaySwitch)) {
                    DeletionResult.Failure(e)
                } else {
                    DeletionResult.Success(wasExisting = false)
                }
            } catch (checkException: PathException) {
                DeletionResult.Failure(e)
            }
        }
    }

    suspend fun APathLookup<*>.toDeletionMatch() = ExpendablesFilter.Match.Deletion(identifier, this)

    private sealed class DeletionResult {
        data class Success(val wasExisting: Boolean) : DeletionResult()
        data class Failure(val error: Exception) : DeletionResult()
    }

    companion object {
        private val TAG = logTag("AppCleaner", "BaseExpendablesFilter")
    }
}
