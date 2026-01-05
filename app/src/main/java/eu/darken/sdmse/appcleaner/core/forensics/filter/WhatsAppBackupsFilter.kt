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
import java.time.Duration
import java.time.Instant
import javax.inject.Inject
import javax.inject.Provider

@Reusable
class WhatsAppBackupsFilter @Inject constructor(
    private val gatewaySwitch: GatewaySwitch,
) : BaseExpendablesFilter() {

    override suspend fun initialize() {
        log(TAG) { "initialize()" }
    }

    override suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pfpSegs: Segments
    ): ExpendablesFilter.Match? {
        // 1. Fail Fast: Check Package (HashSet O(1))
        if (!VALID_PKGS.contains(pkgId)) return null

        // 2. Fail Fast: Check Area (HashSet O(1))
        // Fixed bug: Was checking if set contains SDCARD constant, not the actual areaType
        if (!VALID_LOCS.contains(areaType)) return null

        // 3. Fail Fast: Ignored Files (HashSet O(1))
        if (pfpSegs.isNotEmpty() && IGNORED_FILES.contains(pfpSegs.last())) return null

        // 4. Structural Path Check
        // Path must be at least: .../WhatsApp/Databases/file (Size >= 3)
        val size = pfpSegs.size
        if (size < 3) return null

        // Check immediate parent folder (Databases/Backups)
        val folderName = pfpSegs[size - 2]
        if (!VALID_FOLDERS.contains(folderName)) return null

        // Check grandparent folder (WhatsApp/WhatsApp Business) to ensure we aren't deleting generic "Backups" folders
        // Note: We check containment in VALID_PARENTS set rather than expensive prefix iterations.
        // This covers both /sdcard/WhatsApp/... and /sdcard/Android/media/com.whatsapp/WhatsApp/...
        val parentName = pfpSegs[size - 3]
        if (!VALID_PARENTS.contains(parentName)) return null

        // 5. File Name Pattern Check
        val fileName = pfpSegs.last()
        
        // Optimization: Cheap string checks before heavy Regex
        // WhatsApp incremental backups usually contain ".1." and end with a crypt extension
        if (!fileName.contains(".1.") || !fileName.contains(".crypt")) return null

        // Regex check
        if (FILE_REGEXES.none { it.matches(fileName) }) return null

        // 6. Age Check
        // Filter out files modified within the last 24 hours
        val modifiedAt = target.modifiedAt
        return if (modifiedAt == Instant.EPOCH) {
            null
        } else if (Duration.between(modifiedAt, Instant.now()) > OLD_BACKUP_THRESHOLD) {
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
        private val filterProvider: Provider<WhatsAppBackupsFilter>
    ) : ExpendablesFilter.Factory {
        override suspend fun isEnabled(): Boolean = settings.filterWhatsAppBackupsEnabled.value()
        override suspend fun create(): ExpendablesFilter = filterProvider.get()
    }

    @InstallIn(SingletonComponent::class)
    @Module
    abstract class DIM {
        @Binds @IntoSet abstract fun mod(mod: Factory): ExpendablesFilter.Factory
    }

    companion object {
        private val TAG = logTag("AppCleaner", "Scanner", "Filter", "WhatsApp", "Backups")
        private val OLD_BACKUP_THRESHOLD: Duration = Duration.ofDays(1)

        private val IGNORED_FILES: Set<String> = setOf(
            ".nomedia"
        )
        
        private val VALID_LOCS = setOf(
            DataArea.Type.SDCARD,
            DataArea.Type.PUBLIC_MEDIA
        )

        private val VALID_PKGS = setOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
        ).map { it.toPkgId() }.toSet()

        private val VALID_FOLDERS = setOf(
            "Databases",
            "Backups"
        )

        // Parents that constitute a valid WhatsApp directory structure
        private val VALID_PARENTS = setOf(
            "WhatsApp",
            "WhatsApp Business",
            "com.whatsapp",
            "com.whatsapp.w4b"
        )

        private val FILE_REGEXES: List<Regex> = listOf(
            Regex("msgstore-.+?\\.1\\.db\\.crypt\\d+"),
            Regex("backup_settings-.+?\\.1\\.json\\.crypt\\d+"),
            Regex("chatsettingsbackup-.+?\\.1\\.db\\.crypt\\d+"),
            Regex("commerce_backup-.+?\\.1\\.db\\.crypt\\d+"),
            Regex("stickers-.+?\\.1\\.db\\.crypt\\d+"),
            Regex("wa-.+?\\.1\\.db\\.crypt\\d+"),
            Regex("wallpapers-.+?\\.1\\.backup\\.crypt\\d+"),
        )
    }
}
