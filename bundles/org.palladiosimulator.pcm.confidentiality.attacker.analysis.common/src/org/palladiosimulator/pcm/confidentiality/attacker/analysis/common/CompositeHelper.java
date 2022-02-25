package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.core.composition.AssemblyConnector;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.core.composition.ProvidedDelegationConnector;
import org.palladiosimulator.pcm.repository.CompositeComponent;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.system.System;

/**
 * Helper class for handling composite components
 * 
 * @author Patrick Spiesberger
 *
 */
public class CompositeHelper {

	/**
	 * checks if given component is a CompositeComponent
	 */
	public static boolean isCompositeComponent(AssemblyContext context) {
		if (context.getEncapsulatedComponent__AssemblyContext() instanceof CompositeComponent) {
			return true;
		}
		return false; // BasicComponent
	}


	/*
	 * Returns all connected components. Caution: No components within a composite
	 * component are returned. The getDeligatedCompositeComponents method is used
	 * for this
	 */
	public static List<AssemblyContext> getAdjacentComponents(final AssemblyContext component, System system) {
		final var targetConnectors = getTargetedConnectors(component, system);

		final var targetComponents = targetConnectors.stream()
				.map(AssemblyConnector::getProvidingAssemblyContext_AssemblyConnector)
				.filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList());

		targetComponents
				.addAll(targetConnectors.stream().map(AssemblyConnector::getRequiringAssemblyContext_AssemblyConnector)
						.filter(e -> !EcoreUtil.equals(e, component)).collect(Collectors.toList()));
		return targetComponents;
	}

	public static List<AssemblyConnector> getTargetedConnectors(final AssemblyContext component, final System system) {
		return system.getConnectors__ComposedStructure().stream().filter(AssemblyConnector.class::isInstance)
				.map(AssemblyConnector.class::cast)
				.filter(e -> EcoreUtil.equals(e.getRequiringAssemblyContext_AssemblyConnector(), component)
						|| EcoreUtil.equals(e.getProvidingAssemblyContext_AssemblyConnector(), component))
				.collect(Collectors.toList());
	}

	private static List<ProvidedDelegationConnector> getDelicatedConnectors(final AssemblyContext component,
			final System system) {
		return system.getConnectors__ComposedStructure().stream().filter(ProvidedDelegationConnector.class::isInstance)
				.map(ProvidedDelegationConnector.class::cast)
				.filter(e -> EcoreUtil.equals(e.getAssemblyContext_ProvidedDelegationConnector(), component))
				.collect(Collectors.toList());
	}

	/*
	 * Returns all delegated components. Caution: the returned subcomponents are part of
	 * the main component. The getAdjacentComponents method is used
	 * for adjacent components, which are not part of the composite component
	 */
	public static List<AssemblyContext> getDelegatedCompositeComponents(final AssemblyContext component,
			System system) {
		final var targetConnectors = getDelicatedConnectors(component, system);

		AssemblyContextDetail detail = CollectionHelper.getAssemblyContextDetail(List.of(component)).get(0);

		List<AssemblyContext> assemblies = new LinkedList<>();
		for (ProvidedDelegationConnector connector : targetConnectors) {

			var innerRole = connector.getInnerProvidedRole_ProvidedDelegationConnector()
					.getProvidedInterface__OperationProvidedRole();
			var outerRole = connector.getOuterProvidedRole_ProvidedDelegationConnector()
					.getProvidedInterface__OperationProvidedRole();

			for (AssemblyContext assembly : detail.getCompromisedComponents()) {
				var element = assembly.getEncapsulatedComponent__AssemblyContext();

				var interfacesList = element.getProvidedRoles_InterfaceProvidingEntity().stream()
						.filter(OperationProvidedRole.class::isInstance).map(OperationProvidedRole.class::cast)
						.map(OperationProvidedRole::getProvidedInterface__OperationProvidedRole)
						.collect(Collectors.toList());

				if (interfacesList.contains(innerRole)) {
					assemblies.add(assembly);
				} else if (interfacesList.contains(outerRole)) {
					assemblies.add(assembly);
				}
			}
		}
		return assemblies;
	}

	public static boolean detailContainsAssembly(AssemblyContextDetail detail, AssemblyContext context) {
		// Start at second element, since the first element is the component itself
		for (int i = 1; i < detail.getCompromisedComponents().size(); i++) {
			if (EcoreUtil.equals(detail.getCompromisedComponents().get(i), context)) {
				return true;
			}
		}
		return false;
	}

	public static List<AssemblyContextDetail> createDetails(AssemblyContextDetail detail,
			List<AssemblyContext> targetComponents) {
		List<AssemblyContextDetail> detailsToAttack = new LinkedList<>();
		for (AssemblyContext assembly : targetComponents) {
			AssemblyContextDetail assemblyDetail = AttackerFactory.eINSTANCE.createAssemblyContextDetail();
			assemblyDetail.getCompromisedComponents().addAll(detail.getCompromisedComponents());
			assemblyDetail.getCompromisedComponents().add(assembly);
			assemblyDetail.setEntityName(detail.getEntityName());
			assemblyDetail.setId(detail.getId());
			detailsToAttack.add(assemblyDetail);
		}
		return detailsToAttack;
	}

}
