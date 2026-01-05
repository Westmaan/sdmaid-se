package eu.darken.sdmse.appcleaner.core.forensics.filter

import eu.darken.sdmse.common.areas.DataArea
import eu.darken.sdmse.common.pkgs.Pkg

/**
 * Maps a specific storage location and directory structure to a target Package ID.
 *
 * @param location The storage area (e.g. SDCARD, PUBLIC_MEDIA).
 * @param pkgId The package ID that owns this backup structure.
 * @param parentDir The root directory name (e.g. "WhatsApp" or "Android/media/com.whatsapp").
 * @param subDir The specific target subdirectory (e.g. "Databases" or "Backups").
 */
data class WhatsAppMapping(
    val location: DataArea.Type,
    val pkgId: Pkg.Id,
    val parentDir: String,
    val subDir: String
)
