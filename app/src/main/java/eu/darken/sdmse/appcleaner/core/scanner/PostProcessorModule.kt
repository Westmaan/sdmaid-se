package eu.darken.sdmse.appcleaner.core.scanner

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.ElementsIntoSet
import eu.darken.sdmse.appcleaner.core.AppCleanerSettings
import eu.darken.sdmse.appcleaner.core.scanner.processor.*
import eu.darken.sdmse.common.datastore.value

@InstallIn(SingletonComponent::class)
@Module
object PostProcessorModule {

    @Provides
    @ElementsIntoSet
    fun provideSystemProcessors(
        emptyFolderProcessor: EmptyFolderProcessor,
        emptyFileProcessor: EmptyFileProcessor,
        dalvikCacheProcessor: DalvikCacheProcessor,
    ): Set<PostProcessor> = setOf(
        emptyFolderProcessor,
        emptyFileProcessor,
        dalvikCacheProcessor,
    )

    @Provides
    @ElementsIntoSet
    fun provideConditionalProcessors(
        settings: AppCleanerSettings,
        largeCacheProcessor: LargeCacheProcessor,
    ): Set<PostProcessor> {
        val processors = mutableSetOf<PostProcessor>()
        if (settings.processorLargeCachesEnabled.value) {
            processors.add(largeCacheProcessor)
        }
        return processors
    }

}
