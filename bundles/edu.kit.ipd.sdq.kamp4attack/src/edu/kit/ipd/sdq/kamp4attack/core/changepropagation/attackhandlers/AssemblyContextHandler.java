package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandler;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public abstract class AssemblyContextHandler extends AttackHandler {

	protected AssemblyContextHandler(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	/*
	 * This method separates the AssemblyContextDetails that are not composed from
	 * the composed components. Unassembled components are considered as
	 * AssemblyContext, assembled components are considered separately (recursively)
	 * into their AssemblyContexts
	 */
	public void attackAssemblyContextDetail(final Collection<AssemblyContextDetail> components,
			final CredentialChange change, final EObject source) {
		List<CompromisedAssembly> compromisedSingleComponent = new LinkedList<>();

		for (AssemblyContextDetail detail : components) {
			if (detail.getCompromisedComponents().size() == 1) {
				Optional<CompromisedAssembly> element = attackComponent(detail.getCompromisedComponents().get(0),
						change, source);
				if (element.isPresent()) {
					compromisedSingleComponent.add(element.get());
				}
			} else {
				final var newCompromisedComponent = filterExsitingComponent(attackComponent(detail, change, source),
						change);
				if (!newCompromisedComponent.isEmpty()) {
					handleDataExtraction(newCompromisedComponent);
					change.setChanged(true);
					change.getCompromisedassembly().addAll(newCompromisedComponent);
					CollectionHelper.addService(newCompromisedComponent,
							getModelStorage().getVulnerabilitySpecification(), change);
				}
			}
		}
		final var newCompromisedComponent = filterExsitingComponent(compromisedSingleComponent, change);
		if (!newCompromisedComponent.isEmpty()) {
			handleDataExtraction(newCompromisedComponent);
			change.setChanged(true);
			change.getCompromisedassembly().addAll(newCompromisedComponent);
			CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
					change);
		}

	}

	public void attackAssemblyContext(final Collection<AssemblyContext> components, final CredentialChange change,
			final EObject source) {
		final var compromisedComponent = components.stream().map(e -> attackComponent(e, change, source))
				.flatMap(Optional::stream).collect(Collectors.toList());
		final var newCompromisedComponent = filterExsitingComponent(compromisedComponent, change);
		if (!newCompromisedComponent.isEmpty()) {
			handleDataExtraction(newCompromisedComponent);
			change.setChanged(true);
			change.getCompromisedassembly().addAll(newCompromisedComponent);
			CollectionHelper.addService(newCompromisedComponent, getModelStorage().getVulnerabilitySpecification(),
					change);
		}

	}

	private void handleDataExtraction(final Collection<CompromisedAssembly> components) {

		Collection<AssemblyContext> filteredComponents = components.stream()
				.map(CompromisedAssembly::getAffectedAssembly).collect(Collectors.toList());

		filteredComponents = CollectionHelper.removeDuplicates(filteredComponents);

		final var dataList = filteredComponents.stream().distinct()
				.flatMap(component -> DataHandler.getData(component).stream()).collect(Collectors.toList());

		getDataHandler().addData(dataList);
	}

	protected abstract Collection<CompromisedAssembly> attackComponent(AssemblyContextDetail component,
			CredentialChange change, EObject source);

	protected abstract Optional<CompromisedAssembly> attackComponent(AssemblyContext component, CredentialChange change,
			EObject source);

	private Collection<CompromisedAssembly> filterExsitingComponent(final Collection<CompromisedAssembly> components,
			final CredentialChange change) {
		return components.stream().filter(component -> !containsComponent(component, change))
				.collect(Collectors.toList());

	}

	private boolean containsComponent(final CompromisedAssembly component, final CredentialChange change) {
		return change.getCompromisedassembly().stream().anyMatch(referenceComponent -> EcoreUtil
				.equals(referenceComponent.getAffectedElement(), component.getAffectedElement()));
	}

}
