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
class RecycleBinsFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_trash_files.json")
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

        // 2. Specific Rule: Android/.Trash/<pkg>/file
        if (size >= 4) {
            // Check literal "android" and ".trash" without allocating new strings
            if (SEGMENT_ANDROID.equals(pfpSegs[0], ignoreCase = true) &&
                SEGMENT_DOT_TRASH.equals(pfpSegs[1], ignoreCase = true) &&
                pkgId.name.equals(pfpSegs[2], ignoreCase = true)
            ) {
                return target.toDeletionMatch()
            }
        }

        // 3. General Trash Folders Check
        // Requirements: Must be in specific Areas AND (if SDCARD, must not be inside Android folder)
        if (AREAS.contains(areaType)) {
            // Optimization: If SDCARD, ensure we are NOT in the "Android" folder.
            // This replaces the expensive !segs("Android").isAncestorOf(...) check.
            val isSdCardAndroid = areaType == DataArea.Type.SDCARD &&
                    size > 0 &&
                    SEGMENT_ANDROID.equals(pfpSegs[0], ignoreCase = true)

            if (!isSdCardAndroid) {
                // Check: topdir/.trash/file
                if (size >= 3) {
                    if (TRASH_FOLDERS.contains(pfpSegs[1].lowercase())) {
                        return target.toDeletionMatch()
                    }
                }

                // Check: topdir/files/.trash/file
                if (size >= 4) {
                    if (SEGMENT_FILES.equals(pfpSegs[1], ignoreCase = true) &&
                        TRASH_FOLDERS.contains(pfpSegs[2].lowercase())
                    ) {
                        return target.toDeletionMatch()
                    }
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
        private val filterProvider: Provider<RecycleBinsFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterRecycleBinsEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "RecycleBins")
        private const val SEGMENT_FILES = "files"
        private const val SEGMENT_ANDROID = "android"
        private const val SEGMENT_DOT_TRASH = ".trash"

        private val AREAS = setOf(
            DataArea.Type.SDCARD,
            DataArea.Type.PRIVATE_DATA,
            DataArea.Type.PUBLIC_DATA,
            DataArea.Type.PUBLIC_MEDIA,
        )

        // Optimized: HashSet for O(1) lookup
        private val TRASH_FOLDERS: Set<String> = setOf(
            ".trash", "trash",
            ".trashfiles", "trashfiles",
            ".trashbin", "trashbin",
            ".recycle", "recycle",
            ".recyclebin", "recyclebin",
            ".garbage"
        )

        private val IGNORED_FILES: Set<String> = setOf(
            ".nomedia",
        )
    }
}
