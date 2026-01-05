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
import eu.darken.sdmse.appcleaner.core.forensics.sieves.DynamicAppSieve2
import eu.darken.sdmse.common.areas.DataArea
import eu.darken.sdmse.common.datastore.value
import eu.darken.sdmse.common.debug.logging.log
import eu.darken.sdmse.common.debug.logging.logTag
import eu.darken.sdmse.common.files.APath
import eu.darken.sdmse.common.files.APathLookup
import eu.darken.sdmse.common.files.GatewaySwitch
import eu.darken.sdmse.common.files.Segments
import eu.darken.sdmse.common.pkgs.Pkg
import eu.darken.sdmse.common.pkgs.toPkgId
import eu.darken.sdmse.common.sieve.NameCriterium
import eu.darken.sdmse.common.sieve.SegmentCriterium
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class WhatsAppSentFilter @Inject constructor(
    private val dynamicSieveFactory: DynamicAppSieve2.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: DynamicAppSieve2

    override suspend fun initialize() {
        log(TAG) { "initialize()" }

        val defaultExclusions = setOf(NameCriterium(".nomedia", mode = NameCriterium.Mode.Equal()))
        val configs = mutableSetOf<DynamicAppSieve2.MatchConfig>()

        TARGET_APPS.forEach { (pkg, folderName) ->
            val pkgSet = setOf(pkg.toPkgId())

            // Generate criteria for both legacy SDCARD paths and Android 11+ Public Media paths
            val pathMappings = listOf(
                DataArea.Type.SDCARD to folderName,
                DataArea.Type.PUBLIC_MEDIA to "$pkg/$folderName"
            )

            pathMappings.forEach { (area, basePath) ->
                val criteria = mutableSetOf<DynamicAppSieve2.Criterium>()
                val mediaBase = "$basePath/Media/$folderName"

                // Add "Sent" folder criteria for all media types
                MEDIA_TYPES.forEach { type ->
                    criteria.add(
                        SegmentCriterium("$mediaBase $type/Sent", SegmentCriterium.Mode.Ancestor())
                    )
                }

                configs.add(
                    DynamicAppSieve2.MatchConfig(
                        pkgNames = pkgSet,
                        areaTypes = setOf(area),
                        pfpCriteria = criteria,
                        pfpExclusions = defaultExclusions,
                    )
                )
            }
        }

        sieve = dynamicSieveFactory.create(configs)
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        // Optimization: Fail fast if the package is not WhatsApp or WA Business.
        if (!TARGET_PACKAGES.contains(pkgId.name)) return null

        return if (pfpSegs.isNotEmpty() && sieve.matches(pkgId, target, areaType, pfpSegs)) {
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
        private val filterProvider: Provider<WhatsAppSentFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterWhatsAppSentEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "WhatsApp", "Sent")

        private const val PKG_WHATSAPP = "com.whatsapp"
        private const val PKG_BUSINESS = "com.whatsapp.w4b"

        private val TARGET_PACKAGES = setOf(PKG_WHATSAPP, PKG_BUSINESS)

        // Map Package Name to Root Folder Name
        private val TARGET_APPS = mapOf(
            PKG_WHATSAPP to "WhatsApp",
            PKG_BUSINESS to "WhatsApp Business"
        )

        private val MEDIA_TYPES = listOf(
            "Video",
            "Animated Gifs",
            "Images",
            "Audio",
            "Documents"
        )
    }
}
