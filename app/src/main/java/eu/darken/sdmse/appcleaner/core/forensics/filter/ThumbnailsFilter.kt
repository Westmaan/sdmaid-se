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
class ThumbnailsFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    environment: StorageEnvironment,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    // Optimized: Use HashSet for O(1) lookup
    private val cacheFolderPrefixes = environment.ourCacheDirs.map { it.name }.toHashSet()
    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_thumbnail_files.json")
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        val size = pfpSegs.size
        if (size == 0) return null

        // 1. Fail Fast: Check ignored files (O(1))
        if (IGNORED_FILES.contains(pfpSegs.last().lowercase())) {
            return null
        }

        // 2. Check: Top-level hidden folder (e.g. /.thumbnails/...)
        if (size >= 2 && HIDDEN_FOLDERS.contains(pfpSegs[0].lowercase())) {
            return target.toDeletionMatch()
        }

        // 3. Exclusion: Default Cache Folders
        // Check: package/cache/file
        // Logic: If the first segment is the package name, and the second is a known cache dir, ignore it (handled by other filters).
        if (size >= 2) {
            if (pkgId.name.equals(pfpSegs[0], ignoreCase = true) &&
                cacheFolderPrefixes.contains(pfpSegs[1]) // cacheFolderPrefixes keys are usually lowercase or standard
            ) {
                return null
            }
        }

        // 4. Check: package/.thumbnails/file
        if (size >= 3) {
            if (HIDDEN_FOLDERS.contains(pfpSegs[1].lowercase())) {
                return target.toDeletionMatch()
            }
        }

        // 5. Deep Checks (Size >= 4)
        if (size >= 4) {
            val segment1 = pfpSegs[1]
            val segment2Lower = pfpSegs[2].lowercase()

            // Check: package/files/.thumbnails/file
            if (SEGMENT_FILES.equals(segment1, ignoreCase = true) &&
                HIDDEN_FOLDERS.contains(segment2Lower)
            ) {
                return target.toDeletionMatch()
            }

            // Check: sdcard/Huawei/Themes/.cache/file
            if (areaType == DataArea.Type.SDCARD &&
                HIDDEN_FOLDERS.contains(segment2Lower)
            ) {
                return target.toDeletionMatch()
            }
        }

        // 6. Sieve Check
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
        private val filterProvider: Provider<ThumbnailsFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterThumbnailsEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "Thumbnails")
        private const val SEGMENT_FILES = "files"

        // Optimized: HashSet for O(1) lookup
        private val HIDDEN_FOLDERS: Set<String> = setOf(
            ".thumbs",
            "thumbs",
            ".thumbnails",
            "thumbnails",
            "albumthumbs",
        )

        // Optimized: HashSet for O(1) lookup
        private val IGNORED_FILES: Set<String> = setOf(
            ".nomedia"
        )
    }
}
