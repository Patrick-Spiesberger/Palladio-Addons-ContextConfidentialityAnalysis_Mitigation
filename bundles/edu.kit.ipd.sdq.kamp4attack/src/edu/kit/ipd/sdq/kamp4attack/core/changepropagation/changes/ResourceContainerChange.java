package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.allocation.AllocationContext;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.PCMAttributeProvider;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;

import edu.kit.ipd.sdq.kamp.architecture.ArchitectureModelLookup;
import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.CacheCompromised;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.LinkingResourceHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.ResourceContainerHandler;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.changes.propagationsteps.ResourceContainerPropagation;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedResource;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class ResourceContainerChange extends Change<ResourceContainer>
		implements ResourceContainerPropagation {

	public ResourceContainerChange(final BlackboardWrapper v, CredentialChange change) {
		super(v, change);
	}

	@Override
	protected Collection<ResourceContainer> loadInitialMarkedItems() {
		return ArchitectureModelLookup.lookUpMarkedObjectsOfAType(this.modelStorage, ResourceContainer.class);
	}

	protected List<ResourceContainer> getInfectedResourceContainers() {
		return this.changes.getCompromisedresource().stream().map(CompromisedResource::getAffectedElement)
				.collect(Collectors.toList());
	}

	@Override
	public void calculateResourceContainerToContextPropagation() {
		final var listInfectedContainer = getInfectedResourceContainers();

		final var streamAttributeProvider = this.modelStorage.getSpecification().getAttributeprovider().stream()
				.filter(PCMAttributeProvider.class::isInstance).map(PCMAttributeProvider.class::cast)
				.filter(e -> listInfectedContainer.stream()
						.anyMatch(f -> EcoreUtil.equals(e.getResourcecontainer(), f)));

		updateFromContextProviderStream(this.changes, streamAttributeProvider);
	}

	@Override
	public void calculateResourceContainerToRemoteAssemblyContextPropagation() {
		final var listInfectedContainer = getInfectedResourceContainers();

		for (final var resource : listInfectedContainer) {
			final var resources = getConnectedResourceContainers(resource);
			var assemblycontext = CollectionHelper.getAssemblyContext(resources, this.modelStorage.getAllocation());

			var assemblyContextDetail = CollectionHelper.getAssemblyContextDetail(assemblycontext);

			final var handler = getAssemblyHandler();
			assemblyContextDetail = CollectionHelper.removeDuplicates(assemblyContextDetail).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
			handler.attackAssemblyContextDetail(assemblyContextDetail, this.changes, resource, getAttacker());

			handleSeff(this.changes, assemblycontext, resource);
		}

	}

	protected abstract void handleSeff(CredentialChange changes, List<AssemblyContext> components,
			ResourceContainer source);

	protected abstract AssemblyContextHandler getAssemblyHandler();

	@Override
	public void calculateResourceContainerToLocalAssemblyContextPropagation() {
		final var listInfectedContainer = getInfectedResourceContainers();

		for (final var resource : listInfectedContainer) {
			final var localComponents = this.modelStorage.getAllocation().getAllocationContexts_Allocation().stream()
					.filter(e -> EcoreUtil.equals(resource, e.getResourceContainer_AllocationContext()))
					.map(AllocationContext::getAssemblyContext_AllocationContext)
					.filter(e -> !CacheCompromised.instance().compromised(e));

			final var streamChanges = localComponents
					.map(e -> HelperCreationCompromisedElements.createCompromisedAssembly(e,
							CollectionHelper.getAssemblyContextDetail(List.of(e)).get(0), List.of(resource)));

			final var listChanges = streamChanges.filter(e -> this.changes.getCompromisedassembly().stream()
					.noneMatch(f -> EcoreUtil.equals(f.getAffectedElement().getCompromisedComponents(),
							e.getAffectedElement().getCompromisedComponents())))
					.collect(Collectors.toList());

			if (!listChanges.isEmpty()) {
				this.changes.getCompromisedassembly().addAll(listChanges);
				CollectionHelper.addService(listChanges, this.modelStorage.getVulnerabilitySpecification(),
						this.changes);
				this.changes.setChanged(true);
			}
		}
	}

	@Override
	public void calculateResourceContainerToResourcePropagation() {
		final var listInfectedContainer = getInfectedResourceContainers();

		for (final var resource : listInfectedContainer) {
			final var resources = getConnectedResourceContainers(resource).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());

			final var handler = getResourceHandler();
			handler.attackResourceContainer(resources, this.changes, resource, getAttacker());
		}

	}

	protected abstract ResourceContainerHandler getResourceHandler();

	@Override
	public void calculateResourceContainerToLinkingResourcePropagation() {
		final var listInfectedContainer = getInfectedResourceContainers();

		for (final var resource : listInfectedContainer) {
			final var linkinResources = getLinkingResource(resource).stream()
					.filter(e -> !CacheCompromised.instance().compromised(e)).collect(Collectors.toList());
			final var handler = getLinkingHandler();
			handler.attackLinkingResource(linkinResources, this.changes, resource, getAttacker());
		}

	}

	protected abstract LinkingResourceHandler getLinkingHandler();

}
