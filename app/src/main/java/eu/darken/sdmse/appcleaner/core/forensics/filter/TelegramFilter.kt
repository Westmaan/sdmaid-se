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
import eu.darken.sdmse.common.sieve.SegmentCriterium.Mode.Ancestor
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class TelegramFilter @Inject constructor(
    private val dynamicSieveFactory: DynamicAppSieve2.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: DynamicAppSieve2

    override suspend fun initialize() {
        log(TAG) { "initialize()" }

        val commonMediaPaths = setOf(
            "Telegram/Telegram Audio",
            "Telegram/Telegram Documents",
            "Telegram/Telegram Images",
            "Telegram/Telegram Video",
            "Telegram/Telegram Stories"
        ).map { SegmentCriterium(it, Ancestor()) }.toSet()

        val defaultExclusions = setOf(NameCriterium(".nomedia", mode = NameCriterium.Mode.Equal()))
        val standardAreas = setOf(DataArea.Type.SDCARD, DataArea.Type.PUBLIC_DATA)

        val configs = mutableSetOf<DynamicAppSieve2.MatchConfig>()

        // 1. Official Client
        configs.add(
            DynamicAppSieve2.MatchConfig(
                pkgNames = setOf(PKG_OFFICIAL.toPkgId()),
                areaTypes = standardAreas,
                pfpCriteria = commonMediaPaths + commonMediaPaths.map {
                    SegmentCriterium("$PKG_OFFICIAL/files/${it.segment}", Ancestor())
                },
                pfpExclusions = defaultExclusions,
            )
        )

        // 2. Telegram Plus
        configs.add(
            DynamicAppSieve2.MatchConfig(
                pkgNames = setOf(PKG_PLUS.toPkgId()),
                areaTypes = setOf(DataArea.Type.SDCARD),
                pfpCriteria = commonMediaPaths,
                pfpExclusions = defaultExclusions,
            )
        )

        // 3. Telegram X (Challegram)
        val xPaths = setOf(
            "documents", "music", "videos", "video_notes",
            "animations", "voice", "photos", "stories"
        ).map { SegmentCriterium("$PKG_X/files/$it", Ancestor()) }

        configs.add(
            DynamicAppSieve2.MatchConfig(
                pkgNames = setOf(PKG_X.toPkgId()),
                areaTypes = standardAreas,
                pfpCriteria = commonMediaPaths + xPaths,
                pfpExclusions = defaultExclusions,
            )
        )

        // 4. Telegraph
        configs.add(
            DynamicAppSieve2.MatchConfig(
                pkgNames = setOf(PKG_TELEGRAPH.toPkgId()),
                areaTypes = standardAreas,
                pfpCriteria = commonMediaPaths + commonMediaPaths.map {
                    SegmentCriterium("$PKG_TELEGRAPH/files/${it.segment}", Ancestor())
                },
                pfpExclusions = defaultExclusions,
            )
        )

        // 5. Telegram Web
        configs.add(
            DynamicAppSieve2.MatchConfig(
                pkgNames = setOf(PKG_WEB.toPkgId()),
                areaTypes = standardAreas,
                pfpCriteria = commonMediaPaths + commonMediaPaths.map {
                    SegmentCriterium("$PKG_WEB/files/${it.segment}", Ancestor())
                },
                pfpExclusions = defaultExclusions,
            )
        )

        sieve = dynamicSieveFactory.create(configs)
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        // Optimization: Fail fast if the package is not one of the Telegram clients.
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
        private val filterProvider: Provider<TelegramFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterTelegramEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "Telegram")

        private const val PKG_OFFICIAL = "org.telegram.messenger"
        private const val PKG_PLUS = "org.telegram.plus"
        private const val PKG_X = "org.thunderdog.challegram"
        private const val PKG_TELEGRAPH = "ir.ilmili.telegraph"
        private const val PKG_WEB = "org.telegram.messenger.web"

        // Used for fast lookup in match()
        private val TARGET_PACKAGES = setOf(
            PKG_OFFICIAL,
            PKG_PLUS,
            PKG_X,
            PKG_TELEGRAPH,
            PKG_WEB
        )
    }
}
