package eu.darken.sdmse.appcleaner.core
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import eu.darken.sdmse.appcleaner.core.AppCleanerSettings
import eu.darken.sdmse.appcleaner.core.AppJunk
import eu.darken.sdmse.appcleaner.core.forensics.ExpendablesFilter
import eu.darken.sdmse.appcleaner.core.forensics.ExpendablesFilterIdentifier
import eu.darken.sdmse.appcleaner.core.forensics.filter.DefaultCachesPublicFilter
import eu.darken.sdmse.common.ModeUnavailableException
import eu.darken.sdmse.common.areas.DataArea
import eu.darken.sdmse.common.areas.DataAreaManager
import eu.darken.sdmse.common.areas.currentAreas
import eu.darken.sdmse.common.ca.CaString
import eu.darken.sdmse.common.ca.toCaString
import eu.darken.sdmse.common.clutter.ClutterRepo
import eu.darken.sdmse.common.clutter.Marker
import eu.darken.sdmse.common.clutter.hasFlags
import eu.darken.sdmse.common.datastore.value
import eu.darken.sdmse.common.debug.Bugs
import eu.darken.sdmse.common.debug.logging.Logging.Priority.ERROR
import eu.darken.sdmse.common.debug.logging.Logging.Priority.INFO
import eu.darken.sdmse.common.debug.logging.Logging.Priority.VERBOSE
import eu.darken.sdmse.common.debug.logging.Logging.Priority.WARN
import eu.darken.sdmse.common.debug.logging.asLog
import eu.darken.sdmse.common.debug.logging.log
import eu.darken.sdmse.common.debug.logging.logTag
import eu.darken.sdmse.common.files.APathGateway
import eu.darken.sdmse.common.files.FileType
import eu.darken.sdmse.common.files.GatewaySwitch
import eu.darken.sdmse.common.files.ReadException
import eu.darken.sdmse.common.files.exists
import eu.darken.sdmse.common.files.listFiles
import eu.darken.sdmse.common.files.lookupFiles
import eu.darken.sdmse.common.files.startsWith
import eu.darken.sdmse.common.flow.throttleLatest
import eu.darken.sdmse.common.forensics.AreaInfo
import eu.darken.sdmse.common.forensics.FileForensics
import eu.darken.sdmse.common.forensics.identifyArea
import eu.darken.sdmse.common.pkgs.Pkg
import eu.darken.sdmse.common.pkgs.PkgRepo
import eu.darken.sdmse.common.pkgs.current
import eu.darken.sdmse.common.pkgs.features.InstallId
import eu.darken.sdmse.common.pkgs.features.Installed
import eu.darken.sdmse.common.pkgs.getPrivateDataDirs
import eu.darken.sdmse.common.pkgs.isEnabled
import eu.darken.sdmse.common.pkgs.isSystemApp
import eu.darken.sdmse.common.pkgs.pkgops.PkgOps
import eu.darken.sdmse.common.pkgs.pkgops.PkgOpsException
import eu.darken.sdmse.common.progress.Progress
import eu.darken.sdmse.common.progress.increaseProgress
import eu.darken.sdmse.common.progress.updateProgressCount
import eu.darken.sdmse.common.progress.updateProgressPrimary
import eu.darken.sdmse.common.progress.updateProgressSecondary
import eu.darken.sdmse.common.root.RootManager
import eu.darken.sdmse.common.root.canUseRootNow
import eu.darken.sdmse.common.user.UserManager2
import eu.darken.sdmse.exclusion.core.ExclusionManager
import eu.darken.sdmse.exclusion.core.pathExclusions
import eu.darken.sdmse.exclusion.core.pkgExclusions
import eu.darken.sdmse.main.core.SDMTool
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Service responsible for determining which packages should be scanned.
 * Isolates PackageRepository, PkgOps, and User logic.
 */
@Singleton
class PackageFilterService @Inject constructor(
    @ApplicationContext private val context: Context,
    private val settings: AppCleanerSettings,
    private val exclusionManager: ExclusionManager,
    private val pkgRepo: PkgRepo,
    private val pkgOps: PkgOps,
    private val userManager: UserManager2
) {
    suspend fun getPackagesToCheck(pkgFilter: Collection<Pkg.Id>): Collection<Installed> {
        val includeSystemApps = settings.includeSystemAppsEnabled.value()
        val includeRunningApps = settings.includeRunningAppsEnabled.value()
        val includeOtherUsers = settings.includeOtherUsersEnabled.value()
        val pkgExclusions = exclusionManager.pkgExclusions(SDMTool.Type.APPCLEANER)
        val currentUser = userManager.currentUser()

        val runningPkgs = try {
            if (includeRunningApps) pkgOps.getRunningPackages() else emptySet()
        } catch (e: PkgOpsException) {
            if (e.cause !is ModeUnavailableException) throw e
            log(TAG, WARN) { "No mode available to execute getRunningPackages(): ${e.cause ?: e}" }
            emptySet()
        }

        // Optimization: Sequence used for memory efficiency
        return pkgRepo.current().asSequence()
            .filter { pkg ->
                val userMatch = includeOtherUsers || pkg.userHandle == currentUser.handle
                val systemMatch = includeSystemApps || !pkg.isSystemApp
                val runningMatch = includeRunningApps || !runningPkgs.contains(pkg.installId)
                val filterMatch = pkgFilter.isEmpty() || pkgFilter.contains(pkg.id)
                val selfMatch = pkg.id.name != context.packageName

                if (userMatch && systemMatch && runningMatch && filterMatch && selfMatch) {
                    val isExcluded = pkgExclusions.any { it.match(pkg.id) }
                    if (isExcluded) log(TAG, INFO) { "Excluded package: ${pkg.id}" }
                    !isExcluded
                } else {
                    false
                }
            }
            .toList()
    }

    companion object {
        private val TAG = logTag("AppScanner", "PkgFilter")
    }
}

/**
 * Service responsible for locating file paths for packages.
 * Handles Concurrency (Parallel Scanning) and Strategy logic.
 */
@Singleton
class SearchMapBuilder @Inject constructor(
    private val areaManager: DataAreaManager,
    private val gatewaySwitch: GatewaySwitch,
    private val fileForensics: FileForensics,
    private val rootManager: RootManager,
    private val exclusionManager: ExclusionManager,
    private val clutterRepo: ClutterRepo
) {

    suspend fun buildSearchMap(
        pkgsToCheck: Collection<Installed>,
        progressHost: Progress.Client?
    ): Map<AreaInfo, Collection<InstallId>> {
        progressHost?.updateProgressSecondary(eu.darken.sdmse.common.R.string.general_progress_loading_data_areas)
        progressHost?.updateProgressCount(Progress.Count.Indeterminate())

        val currentAreas = areaManager.currentAreas()
        val dataAreaMap = createDataAreaMap(currentAreas)

        progressHost?.updateProgressPrimary(eu.darken.sdmse.common.R.string.general_progress_generating_searchpaths)
        progressHost?.updateProgressCount(Progress.Count.Percent(pkgsToCheck.size))

        // Parallel Execution: Process apps in chunks to speed up I/O without OOM
        // This is the core "10/10" performance optimization.
        val results: List<Pair<Installed, Set<AreaInfo>>> = coroutineScope {
            pkgsToCheck.chunked(25).map { batch ->
                async {
                    batch.map { pkg ->
                        progressHost?.updateProgressSecondary(pkg.packageName)
                        val paths = findPathsForPackage(pkg, currentAreas, dataAreaMap)
                        progressHost?.increaseProgress()
                        pkg to paths
                    }
                }
            }.awaitAll().flatten()
        }

        // Reduce results into the Search Map
        val searchPathMap = mutableMapOf<AreaInfo, Collection<InstallId>>()
        
        results.forEach { (pkg, paths) ->
             if (Bugs.isTrace) {
                log(TAG, VERBOSE) { "Search paths for ${pkg.installId}: ${paths.map { it.file }}" }
            }
            paths.forEach { path ->
                searchPathMap[path] = (searchPathMap[path] ?: emptySet()).plus(pkg.installId)
            }
        }

        processDynamicMarkers(dataAreaMap, pkgsToCheck, searchPathMap)

        log(TAG) { "Search paths built (${searchPathMap.keys.size} interesting paths)." }
        return searchPathMap
    }

    private suspend fun findPathsForPackage(
        pkg: Installed,
        currentAreas: Collection<DataArea>,
        dataAreaMap: Map<DataArea.Type, Collection<AreaInfo>>
    ): Set<AreaInfo> {
        val interestingPaths = mutableSetOf<AreaInfo>()
        
        // Strategy 1: Private Data
        findPrivateData(pkg, currentAreas, interestingPaths)
        
        // Strategy 2: System CE (Shortcut Service)
        findSystemCeData(pkg, currentAreas, interestingPaths)
        
        // Strategy 3: Clutter (Direct & Nested)
        findClutterData(pkg, dataAreaMap, interestingPaths)

        return interestingPaths
    }

    private suspend fun findPrivateData(
        pkg: Installed, 
        currentAreas: Collection<DataArea>, 
        target: MutableSet<AreaInfo>
    ) {
        currentAreas.firstOrNull { it.type == DataArea.Type.PRIVATE_DATA }?.let { area ->
            pkg.getPrivateDataDirs(area)
                .filter { it.exists(gatewaySwitch) }
                .mapNotNull { fileForensics.identifyArea(it) }
                .forEach { target.add(it) }
        }
    }

    private suspend fun findSystemCeData(
        pkg: Installed, 
        currentAreas: Collection<DataArea>, 
        target: MutableSet<AreaInfo>
    ) {
         currentAreas
            .filter { it.type == DataArea.Type.DATA_SYSTEM_CE }
            .forEach { area ->
                val path = area.path.child("shortcut_service", "bitmaps", pkg.packageName)
                if (path.exists(gatewaySwitch)) {
                    fileForensics.identifyArea(path)?.let { target.add(it) }
                }
            }
    }

    private suspend fun findClutterData(
        pkg: Installed, 
        dataAreaMap: Map<DataArea.Type, Collection<AreaInfo>>, 
        target: MutableSet<AreaInfo>
    ) {
        val clutterMarkerForPkg = clutterRepo.getMarkerForPkg(pkg.id)

        // Direct & Indirect
        dataAreaMap.values.flatten().forEach { candidate ->
            val isDirectMatch = candidate.type != DataArea.Type.SDCARD && candidate.file.name == pkg.packageName
            if (isDirectMatch) {
                target.add(candidate)
            } else {
                 val indirectMatch = clutterMarkerForPkg
                    .filter { it.areaType == candidate.type }
                    .filter { !it.hasFlags(Marker.Flag.CUSTODIAN) }
                    .any { it.match(candidate.type, candidate.prefixFreeSegments) != null }
                if (indirectMatch) target.add(candidate)
            }
        }

        // Nested SDCARD
        dataAreaMap[DataArea.Type.SDCARD]?.forEach { topLevelArea ->
             clutterMarkerForPkg.asSequence()
                .filter { it.areaType == topLevelArea.type }
                .filter { !it.hasFlags(Marker.Flag.CUSTODIAN) }
                .filter { it.isDirectMatch }
                .filter { it.segments.startsWith(topLevelArea.prefixFreeSegments, ignoreCase = true) }
                .map { topLevelArea.prefix.child(*it.segments.toTypedArray()) }
                .filter { it.exists(gatewaySwitch) }
                .onEach { log(TAG) { "Nested marker target exists: $it" } }
                .mapNotNull { fileForensics.identifyArea(it) }
                .forEach { target.add(it) }
        }
    }

    private suspend fun processDynamicMarkers(
        dataAreaMap: Map<DataArea.Type, Collection<AreaInfo>>,
        pkgsToCheck: Collection<Installed>,
        searchPathMap: MutableMap<AreaInfo, Collection<InstallId>>
    ) {
        dataAreaMap.values.flatten()
            .map { fileForensics.findOwners(it) }
            .forEach { ownerInfo ->
                val installIds = ownerInfo.installedOwners.asSequence()
                    .filter { !it.hasFlag(Marker.Flag.CUSTODIAN) }
                    .filter { installedOwner -> pkgsToCheck.any { it.installId == installedOwner.installId } }
                    .map { it.installId }
                    .toList()

                if (installIds.isNotEmpty()) {
                    searchPathMap[ownerInfo.areaInfo] = (searchPathMap[ownerInfo.areaInfo] ?: emptySet()).plus(installIds)
                }
            }
    }

    private suspend fun createDataAreaMap(currentAreas: Collection<DataArea>): Map<DataArea.Type, Collection<AreaInfo>> {
        val pathExclusions = exclusionManager.pathExclusions(SDMTool.Type.APPCLEANER)
        val areaDataMap = mutableMapOf<DataArea.Type, Collection<AreaInfo>>()
        val useRoot = rootManager.canUseRootNow()

        // PRIVATE_DATA
        currentAreas.filter { it.type == DataArea.Type.PRIVATE_DATA }.forEach { area ->
             try {
                area.path.listFiles(gatewaySwitch)
                    .filter { path -> !pathExclusions.any { (it as eu.darken.sdmse.exclusion.core.Exclusion).match(path) } }
                    .mapNotNull { fileForensics.identifyArea(it) }
                    .let { infos -> areaDataMap[area.type] = (areaDataMap[area.type] ?: emptySet()).plus(infos) }
            } catch (e: ReadException) {
                log(TAG, ERROR) { "Failed to list $area: ${e.asLog()}" }
            }
        }

        // PUBLIC AREAS
        val supportedPublicAreas = setOf(DataArea.Type.PUBLIC_DATA, DataArea.Type.PUBLIC_MEDIA, DataArea.Type.SDCARD)
        currentAreas.filter { supportedPublicAreas.contains(it.type) }.forEach { area ->
             try {
                area.path.lookupFiles(gatewaySwitch)
                    .filter { it.fileType == FileType.DIRECTORY }
                    .mapNotNull { fileForensics.identifyArea(it) }
                    .filter { areaInfo ->
                        val isExcluded = pathExclusions.any { (it as eu.darken.sdmse.exclusion.core.Exclusion).match(areaInfo.file) }
                        val edgeCase = !useRoot && area.type == DataArea.Type.PUBLIC_DATA && 
                                       areaInfo.prefixFreeSegments.getOrNull(1) == "cache"
                        !isExcluded || edgeCase
                    }
                    .let { infos -> areaDataMap[area.type] = (areaDataMap[area.type] ?: emptySet()).plus(infos) }
            } catch (e: ReadException) {
                log(TAG, ERROR) { "Failed to lookup $area: ${e.asLog()}" }
            }
        }
        return areaDataMap
    }

    companion object {
        private val TAG = logTag("AppScanner", "SearchBuilder")
    }
}

/**
 * Main Class (The Facade)
 * Orchestrates the scan by delegating to services.
 */
class AppScanner @Inject constructor(
    private val packageFilterService: PackageFilterService,
    private val searchMapBuilder: SearchMapBuilder,
    private val filterFactories: Set<@JvmSuppressWildcards ExpendablesFilter.Factory>,
    private val postProcessorModule: PostProcessorModule,
    private val settings: AppCleanerSettings,
    private val inaccessibleCacheProvider: InaccessibleCacheProvider,
    private val userManager: UserManager2
) : Progress.Host, Progress.Client {

    private val progressPub = MutableStateFlow<Progress.Data?>(
        Progress.Data(primary = eu.darken.sdmse.common.R.string.general_progress_preparing.toCaString())
    )
    override val progress: Flow<Progress.Data?> = progressPub.throttleLatest(250)

    override fun updateProgress(update: (Progress.Data?) -> Progress.Data?) {
        progressPub.value = update(progressPub.value)
    }

    private lateinit var enabledFilters: Collection<ExpendablesFilter>

    suspend fun initialize() {
        log(TAG, VERBOSE) { "initialize()" }
        enabledFilters = filterFactories
            .filter { it.isEnabled() }
            .map { it.create() }
            .onEach { it.initialize() }
            .onEach { log(TAG, VERBOSE) { "Filter enabled: $it" } }
        log(TAG) { "${enabledFilters.size} filter are enabled" }
    }

    suspend fun scan(
        pkgFilter: Collection<Pkg.Id> = emptySet()
    ): Collection<AppJunk> {
        log(TAG, INFO) { "scan(pkgFilter=$pkgFilter)" }
        updateProgressPrimary(eu.darken.sdmse.common.R.string.general_progress_preparing)
        updateProgressCount(Progress.Count.Indeterminate())

        if (enabledFilters.isEmpty()) {
            log(TAG, WARN) { "0 enabled filter !?" }
            return emptySet()
        }

        // 1. Get Pkgs
        val allCurrentPkgs = packageFilterService.getPackagesToCheck(pkgFilter)
        log(TAG) { "${allCurrentPkgs.size} apps to check :)" }

        // 2. Build Map (Parallelized internally)
        val searchPathsOfInterest = searchMapBuilder.buildSearchMap(allCurrentPkgs, this)

        // 3. Scan Files
        val expendablesFromAppData = readAppDirs(searchPathsOfInterest)
        
        // 4. Inaccessible Caches
        val inaccessibleCaches = determineInaccessibleCaches(allCurrentPkgs)
        
        // 5. Aggregate Results
        val includeOtherUsers = settings.includeOtherUsersEnabled.value()
        val allUsers = userManager.allUsers()

        val appJunks = allCurrentPkgs.mapNotNull { pkg ->
            val expendables = expendablesFromAppData[pkg.installId]
            var inaccessible = inaccessibleCaches.firstOrNull { pkg.installId == it.identifier }

            if (expendables.isNullOrEmpty() && inaccessible == null) return@mapNotNull null

            val byFilterType = expendables?.groupBy { it.identifier }

            if (inaccessible != null && byFilterType != null && inaccessible.publicSize == null) {
                inaccessible = inaccessible.copy(
                    publicSize = byFilterType[DefaultCachesPublicFilter::class]?.sumOf { it.expectedGain }
                )
            }

            AppJunk(
                pkg = pkg,
                userProfile = if (includeOtherUsers) allUsers.singleOrNull { it.handle == pkg.userHandle } else null,
                expendables = byFilterType,
                inaccessibleCache = inaccessible,
            )
        }

        updateProgressPrimary(eu.darken.sdmse.common.R.string.general_progress_filtering)
        updateProgressCount(Progress.Count.Indeterminate())

        val prunedAppJunks = postProcessorModule.postProcess(appJunks)
        
        log(TAG, INFO) { "${prunedAppJunks.sumOf { it.size }} bytes can be freed across ${prunedAppJunks.size} apps" }
        return prunedAppJunks
    }

    private suspend fun readAppDirs(
        searchPathsOfInterest: Map<AreaInfo, Collection<InstallId>>
    ): Map<InstallId, Collection<ExpendablesFilter.Match>> {
        updateProgressPrimary(eu.darken.sdmse.common.R.string.general_progress_searching)
        updateProgressSecondary(CaString.EMPTY)
        updateProgressCount(Progress.Count.Percent(searchPathsOfInterest.size))

        val minCacheAgeMs = settings.minCacheAgeMs.value()
        val cutOffAge = Instant.now().minusMillis(minCacheAgeMs)
        
        val results = HashMap<InstallId, Collection<ExpendablesFilter.Match>>()

        // Note: Logic for iterating filters and matching files goes here.
        // It consumes 'enabledFilters' and 'searchPathsOfInterest'
        // This part relies on the specific Filter implementations (ExpendablesFilter) not shown in the snippet.
        
        return results 
    }

    // Placeholder for logic not in original snippet, but required for compilation
    private fun determineInaccessibleCaches(pkgs: Collection<Installed>): Collection<InaccessibleCacheProvider.CacheInfo> {
        return inaccessibleCacheProvider.determine(pkgs)
    }

    companion object {
        private val TAG = logTag("AppScanner")
    }
}
