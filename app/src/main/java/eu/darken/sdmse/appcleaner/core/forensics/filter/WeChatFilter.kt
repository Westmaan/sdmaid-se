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
import eu.darken.sdmse.common.sieve.CriteriaOperator
import eu.darken.sdmse.common.sieve.NameCriterium
import eu.darken.sdmse.common.sieve.SegmentCriterium
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class WeChatFilter @Inject constructor(
    private val dynamicSieveFactory: DynamicAppSieve2.Factory,
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    private lateinit var sieve: DynamicAppSieve2

    override suspend fun initialize() {
        log(TAG) { "initialize()" }

        // Define shared folder criteria once to avoid repetition
        val targetFolders = listOf("sns", "video", "image2", "voice2")
        val folderLogic = CriteriaOperator.Or(
            targetFolders.map {
                SegmentCriterium(it, SegmentCriterium.Mode.Specific(1, backwards = true))
            }.toSet()
        )

        val defaultExclusions = setOf(NameCriterium(".nomedia", NameCriterium.Mode.Equal()))
        val targetPkg = setOf(PKG_WECHAT.toPkgId())

        // 1. SD Card Configuration (Legacy path: tencent/MicroMsg)
        val configSd = DynamicAppSieve2.MatchConfig(
            pkgNames = targetPkg,
            areaTypes = setOf(DataArea.Type.SDCARD),
            pfpCriteria = setOf(
                CriteriaOperator.And(
                    SegmentCriterium("tencent/MicroMsg", SegmentCriterium.Mode.Ancestor()),
                    folderLogic
                )
            ),
            pfpExclusions = defaultExclusions,
        )

        // 2. Data Configuration (Standard path: com.tencent.mm/MicroMsg)
        // Combines Public and Private data types as the relative path logic is identical.
        val configData = DynamicAppSieve2.MatchConfig(
            pkgNames = targetPkg,
            areaTypes = setOf(DataArea.Type.PUBLIC_DATA, DataArea.Type.PRIVATE_DATA),
            pfpCriteria = setOf(
                CriteriaOperator.And(
                    SegmentCriterium("$PKG_WECHAT/MicroMsg", SegmentCriterium.Mode.Ancestor()),
                    folderLogic
                )
            ),
            pfpExclusions = defaultExclusions,
        )

        sieve = dynamicSieveFactory.create(setOf(configSd, configData))
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        // Optimization: Fail fast if the package is not WeChat.
        // This prevents entering the heavy Sieve logic for 99% of scanned files.
        if (pkgId.name != PKG_WECHAT) return null

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
        private val filterProvider: Provider<WeChatFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterWeChatEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "WeChat")
        private const val PKG_WECHAT = "com.tencent.mm"
    }
}
