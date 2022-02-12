package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.palladiosimulator.pcm.allocation.Allocation;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.MitigationHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.context.system.pcm.structure.ServiceRestriction;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;
import org.palladiosimulator.pcm.repository.CompositeComponent;
import org.palladiosimulator.pcm.repository.OperationProvidedRole;
import org.palladiosimulator.pcm.repository.OperationRequiredRole;
import org.palladiosimulator.pcm.repository.OperationSignature;
import org.palladiosimulator.pcm.repository.Parameter;
import org.palladiosimulator.pcm.repository.RepositoryComponent;
import org.palladiosimulator.pcm.resourceenvironment.ResourceContainer;
import org.palladiosimulator.pcm.seff.ExternalCallAction;
import org.palladiosimulator.pcm.seff.ResourceDemandingSEFF;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class DataHandler {

	private DataHandler() {

	}

	public static Collection<DatamodelAttacker> getData(final AssemblyContext assemblyContext, CredentialChange change,
			final Attacker attacker) {

		var component = assemblyContext.getEncapsulatedComponent__AssemblyContext();
		Collection<DatamodelAttacker> dataAttacker = new LinkedList<>();
		if (component instanceof CompositeComponent) {
			dataAttacker.addAll(getDataHelper(component, assemblyContext, change, attacker));
			for (AssemblyContext assembly : ((CompositeComponent) component).getAssemblyContexts__ComposedStructure()) {
				dataAttacker.addAll(getDataHelper(component, assembly, change, attacker));
			}
		} else {
			dataAttacker.addAll(getDataHelper(component, assemblyContext, change, attacker));
		}
		return dataAttacker;
	}

	private static Collection<DatamodelAttacker> getDataHelper(final RepositoryComponent component,
			final AssemblyContext assemblyContext, CredentialChange change, final Attacker attacker) {
		try {
			final var interfacesList = component.getProvidedRoles_InterfaceProvidingEntity().stream()
					.filter(OperationProvidedRole.class::isInstance).map(OperationProvidedRole.class::cast)
					.map(OperationProvidedRole::getProvidedInterface__OperationProvidedRole)
					.collect(Collectors.toUnmodifiableList());
			final var parameters = interfacesList.stream().flatMap(e -> e.getSignatures__OperationInterface().stream())
					.flatMap(e -> e.getParameters__OperationSignature().stream());
			final var listDataParameter = createDataFromParameter(parameters);

			var interfacesRequired = component.getRequiredRoles_InterfaceRequiringEntity().stream()
					.filter(OperationRequiredRole.class::isInstance).map(OperationRequiredRole.class::cast)
					.map(OperationRequiredRole::getRequiredInterface__OperationRequiredRole);

			interfacesRequired = Stream.concat(interfacesList.stream(), interfacesRequired);
			var listDataReturnTypes = interfacesRequired.flatMap(e -> e.getSignatures__OperationInterface().stream())
					.map(DataHandler::createDataReturnValue).flatMap(Optional::stream).collect(Collectors.toList());

			listDataReturnTypes = listDataReturnTypes.stream()
					.filter(data -> MitigationHelper.isCrackable(data, change, attacker)).collect(Collectors.toList());

			listDataParameter.addAll(listDataReturnTypes);
			listDataParameter.stream().forEach(data -> data.setSource(assemblyContext));
			return listDataParameter;
		} catch (NullPointerException e) {
			return Collections.emptyList();
		}
	}

	private static Optional<DatamodelAttacker> createDataReturnValue(final OperationSignature signature) {
		if (signature.getReturnType__OperationSignature() == null) {
			return Optional.empty();
		}
		final var data = AttackerFactory.eINSTANCE.createDatamodelAttacker();
		data.setDataType(signature.getReturnType__OperationSignature());
		data.setMethod(signature);
		return Optional.of(data);
	}

	private static Collection<DatamodelAttacker> createDataFromParameter(final Stream<Parameter> parameters) {
		return parameters.map(parameter -> {
			final var data = AttackerFactory.eINSTANCE.createDatamodelAttacker();
			data.setDataType(parameter.getDataType__Parameter());
			data.setReferenceName(parameter.getParameterName());
			return data;
		}).collect(Collectors.toList());
	}

	public static List<DatamodelAttacker> getData(final ResourceContainer resource, final Allocation allocation,
			CredentialChange change, Attacker attacker) {
		final var assemblyContexts = CollectionHelper.getAssemblyContext(List.of(resource), allocation);

		for (AssemblyContext assembly : assemblyContexts) {
			var type = assembly.getEncapsulatedComponent__AssemblyContext();
			if (type instanceof CompositeComponent) {
				assemblyContexts.addAll(((CompositeComponent) type).getAssemblyContexts__ComposedStructure());
			}
		}

		return assemblyContexts.stream().flatMap(e -> getData(e, change, attacker).stream())
				.collect(Collectors.toList());
	}

	public static Collection<DatamodelAttacker> getData(ServiceRestriction serviceRestriction, CredentialChange change,
			Attacker attacker) {
		var dataList = getData(serviceRestriction.getService(), change, attacker);
		dataList.stream().forEach(data -> data.setSource(serviceRestriction));
		return dataList;
	}

	private static Collection<DatamodelAttacker> getData(final ResourceDemandingSEFF seff, CredentialChange change,
			Attacker attacker) {
		final var parameterStream = ((OperationSignature) seff.getDescribedService__SEFF())
				.getParameters__OperationSignature().stream();

		var dataSignatureList = DataHandler.createDataFromParameter(parameterStream);

		final var seffList = seff.getSteps_Behaviour().stream().filter(ExternalCallAction.class::isInstance)
				.map(ExternalCallAction.class::cast).map(ExternalCallAction::getCalledService_ExternalService)
				.map(DataHandler::createDataReturnValue).flatMap(Optional::stream)
				.collect(Collectors.toUnmodifiableList());

		final var returnData = createDataReturnValue((OperationSignature) seff.getDescribedService__SEFF());
		if (returnData.isPresent()) {
			dataSignatureList.add(returnData.get());
		}
		dataSignatureList.addAll(seffList);

		dataSignatureList = dataSignatureList.stream()
				.filter(data -> MitigationHelper.isCrackable(data, change, attacker)).collect(Collectors.toList());

		return dataSignatureList;
	}

}
