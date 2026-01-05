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
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class GameFilesFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_downloaded_game_files.json")
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        val size = pfpSegs.size
        if (size == 0) return null

        // 1. Fail Fast: Check ignored files (O(1) lookup)
        if (IGNORED_FILES.contains(pfpSegs.last().lowercase())) {
            return null
        }

        // 2. Check Standard Path: topdir/gamedir/file (Size >= 3)
        if (size >= 3) {
            val segment1 = pfpSegs[1]
            if (TARGET_FOLDERS.contains(segment1.lowercase())) {
                return target.toDeletionMatch()
            }
        }

        // 3. Check Nested Path: topdir/files/gamedir/file (Size >= 4)
        if (size >= 4) {
            // Check "files" using equals ignore case (no allocation)
            if (SEGMENT_FILES.equals(pfpSegs[1], ignoreCase = true)) {
                val segment2 = pfpSegs[2]
                if (TARGET_FOLDERS.contains(segment2.lowercase())) {
                    return target.toDeletionMatch()
                }
            }
        }

        // 4. Sieve Check
        return if (sieve.matches(pkgId, areaType, pfpSegs)) {
            target.toDeletionMatch()
        } else {
            null
        }
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
        private val filterProvider: Provider<GameFilesFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterGameFilesEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "GameFiles")
        private const val SEGMENT_FILES = "files"
        
        // Optimized: Set for O(1) lookup
        private val TARGET_FOLDERS: Set<String> = setOf(
            "unitycache"
        )
        
        // Optimized: Set for O(1) lookup
        private val IGNORED_FILES: Set<String> = setOf(
            ".nomedia",
        )
    }
}
