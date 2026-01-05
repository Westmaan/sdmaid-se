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
class WebViewCacheFilter @Inject constructor(
    private val jsonBasedSieveFactory: JsonAppSieve.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: JsonAppSieve

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
        sieve = jsonBasedSieveFactory.create("expendables/db_webcaches.json")
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        // 1. Fail Fast: Minimum depth for a webview cache is 3 (pkg/app_webview/Cache)
        if (pfpSegs.size < 3) return null

        // 2. Check Ignored Files (O(1))
        if (IGNORED_FILES.contains(pfpSegs.last())) return null

        // 3. Verify Package Ownership
        if (!pkgId.name.equals(pfpSegs[0], ignoreCase = true)) return null

        // 4. Structural Path Matching (Zero Allocation)
        // We replace the loop/prepend logic with direct index checks.
        val segment1 = pfpSegs[1]

        // Branch 1: app_webview
        if (DIR_APP_WEBVIEW.equals(segment1, ignoreCase = true)) {
            val segment2 = pfpSegs[2]
            
            // Check direct children: Cache, GPUCache, Application Cache
            if (WEBVIEW_ROOT_TARGETS.contains(segment2)) {
                return target.toDeletionMatch()
            }
            
            // Check Nested: Service Worker
            if (pfpSegs.size >= 4 && DIR_SERVICE_WORKER == segment2) {
                if (WORKER_TARGETS.contains(pfpSegs[3])) {
                    return target.toDeletionMatch()
                }
            }
        }
        // Branch 2: app_chrome
        else if (DIR_APP_CHROME.equals(segment1, ignoreCase = true)) {
            val segment2 = pfpSegs[2]

            // Check direct children: ShaderCache, GrShaderCache
            if (CHROME_ROOT_TARGETS.contains(segment2)) {
                return target.toDeletionMatch()
            }

            // Check Nested: Default
            if (pfpSegs.size >= 4 && DIR_DEFAULT == segment2) {
                val segment3 = pfpSegs[3]
                
                // Default/Application Cache, Default/GPUCache
                if (CHROME_DEFAULT_TARGETS.contains(segment3)) {
                    return target.toDeletionMatch()
                }

                // Default/Service Worker/
                if (pfpSegs.size >= 5 && DIR_SERVICE_WORKER == segment3) {
                    if (WORKER_TARGETS.contains(pfpSegs[4])) {
                        return target.toDeletionMatch()
                    }
                }
            }
        }

        // 5. Sieve Check
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
        private val filterProvider: Provider<WebViewCacheFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterWebviewEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "Webview")
        
        // Constants for directory names to avoid magic strings
        private const val DIR_APP_WEBVIEW = "app_webview"
        private const val DIR_APP_CHROME = "app_chrome"
        private const val DIR_SERVICE_WORKER = "Service Worker"
        private const val DIR_DEFAULT = "Default"

        // Optimized Sets for O(1) lookup
        private val IGNORED_FILES: Set<String> = setOf(".nomedia")
        
        private val WEBVIEW_ROOT_TARGETS: Set<String> = setOf(
            "Cache", 
            "Application Cache", 
            "GPUCache"
        )
        
        private val CHROME_ROOT_TARGETS: Set<String> = setOf(
            "ShaderCache", 
            "GrShaderCache"
        )
        
        private val CHROME_DEFAULT_TARGETS: Set<String> = setOf(
            "Application Cache", 
            "GPUCache"
        )
        
        private val WORKER_TARGETS: Set<String> = setOf(
            "CacheStorage", 
            "ScriptCache"
        )
    }
}
