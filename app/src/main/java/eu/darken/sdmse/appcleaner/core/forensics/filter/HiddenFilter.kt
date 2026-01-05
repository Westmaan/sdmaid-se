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
class HiddenFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    environment: StorageEnvironment,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private val cacheFolderPrefixes = environment.ourCacheDirs.map { it.name }.toHashSet()
    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_hidden_caches_files.json")
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        val size = pfpSegs.size
        
        if (size >= 2) {
            if (pkgId.name == pfpSegs[0] && cacheFolderPrefixes.contains(pfpSegs[1])) {
                return null
            }
        }

        if (size > 0 && IGNORED_FILES.contains(pfpSegs.last().lowercase())) {
            return null
        }

        if (size == 2 && HIDDEN_CACHE_FILES.contains(pfpSegs[1].lowercase())) {
            return target.toDeletionMatch()
        }

        if (size == 3 && HIDDEN_CACHE_FILES.contains(pfpSegs[2].lowercase())) {
            return target.toDeletionMatch()
        }

        if (size >= 3) {
            if (HIDDEN_CACHE_FOLDERS.contains(pfpSegs[1].lowercase())) {
                return target.toDeletionMatch()
            }
        }

        if (size >= 4) {
            if (pfpSegs[2] == SEGMENT_CACHE_CAPS && pfpSegs[3].contains(UNITY_EXT)) {
                return null
            }

            if (SEGMENT_FILES.equals(pfpSegs[1], ignoreCase = true)) {
                val segment2Lower = pfpSegs[2].lowercase()
                if (HIDDEN_CACHE_FOLDERS.contains(segment2Lower) || SEGMENT_CACHE_LOWER == segment2Lower) {
                    return target.toDeletionMatch()
                }
            }

            if (areaType == DataArea.Type.SDCARD && HIDDEN_CACHE_FOLDERS.contains(pfpSegs[2].lowercase())) {
                return target.toDeletionMatch()
            }
        }

        return if (size > 0 && sieve.matches(pkgId, areaType, pfpSegs)) {
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
        private val filterProvider: Provider<HiddenFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterHiddenCachesEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "HiddenCaches")
        private const val SEGMENT_FILES = "files"
        private const val SEGMENT_CACHE_LOWER = "cache"
        private const val SEGMENT_CACHE_CAPS = "Cache"
        private const val UNITY_EXT = ".unity3d&"

        private val HIDDEN_CACHE_FOLDERS: Set<String> = setOf(
            "tmp", ".tmp",
            "tmpdata", "tmp-data", "tmp_data",
            ".tmpdata", ".tmp-data", ".tmp_data",
            ".temp", "temp",
            "tempdata", "temp-data", "temp_data",
            ".tempdata", ".temp-data", ".temp_data",
            ".cache", "cache", "_cache", "-cache",
            ".caches", "caches", "_caches", "-caches",
            "imagecache", "image-cache", "image_cache",
            ".imagecache", ".image-cache", ".image_cache",
            "imagecaches", "image-caches", "image_caches",
            ".imagecaches", ".image-caches", ".image_caches",
            "videocache", "video-cache", "video_cache",
            ".videocache", ".video-cache", ".video_cache",
            "videocaches", "video-caches", "video_caches",
            ".videocaches", ".video-caches", ".video_caches",
            "mediacache", "media-cache", "media_cache",
            ".mediacache", ".media-cache", ".media-cache",
            "mediacaches", "media-caches", "media_caches",
            ".mediacaches", ".media-caches", ".media_caches",
            "diskcache", "disk-cache", "disk_cache",
            ".diskcache", ".disk-cache", ".disk_cache",
            "diskcaches", "disk-caches", "disk_caches",
            ".diskcaches", ".disk-caches", ".disk_caches",
            "filescache",
            "avfscache"
        )

        private val HIDDEN_CACHE_FILES: Set<String> = setOf(
            "cache.dat",
            "tmp.dat",
            "temp.dat",
            ".temp.jpg"
        )

        private val IGNORED_FILES: Set<String> = setOf(
            ".nomedia"
        )
    }
}
