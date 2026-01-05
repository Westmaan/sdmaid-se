package eu.darken.sdmse.appcleaner.core.forensics

import eu.darken.sdmse.common.areas.DataArea
import eu.darken.sdmse.common.files.APath
import eu.darken.sdmse.common.files.APathLookup
import eu.darken.sdmse.common.files.Segments
import eu.darken.sdmse.common.pkgs.Pkg
import eu.darken.sdmse.common.progress.Progress
import kotlin.reflect.KClass

interface ExpendablesFilter : Progress.Host, Progress.Client {

    val identifier: ExpendablesFilterIdentifier
        get() = this::class

    suspend fun initialize()

    suspend fun match(
        pkgId: Pkg.Id,
        target: APathLookup<APath>,
        areaType: DataArea.Type,
        pathSegments: Segments
    ): Match?

    suspend fun process(targets: Collection<Match>, allMatches: Collection<Match>): ProcessResult

    data class ProcessResult(
        val success: Collection<Match>,
        val failed: Collection<Pair<Match, Exception>>,
    )

    sealed interface Match {
        val identifier: ExpendablesFilterIdentifier
        val lookup: APathLookup<out APath>
        val path: APath
            get() = lookup.lookedUp

        val expectedGain: Long

        data class Deletion(
            override val identifier: ExpendablesFilterIdentifier,
            override val lookup: APathLookup<out APath>,
        ) : Match {
            override val expectedGain: Long
                get() = lookup.size
        }
    }

    interface Factory {
        suspend fun isEnabled(): Boolean
        suspend fun create(): ExpendablesFilter
    }
}

typealias ExpendablesFilterIdentifier = KClass<out ExpendablesFilter>
