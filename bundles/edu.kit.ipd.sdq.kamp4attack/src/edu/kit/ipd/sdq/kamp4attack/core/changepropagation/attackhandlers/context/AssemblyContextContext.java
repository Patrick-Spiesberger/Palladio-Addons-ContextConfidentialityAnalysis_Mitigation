package edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.context;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.EObject;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.AssemblyHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.CollectionHelper;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.HelperCreationCompromisedElements;
import org.palladiosimulator.pcm.confidentiality.attacker.analysis.common.data.DataHandlerAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AttackerFactory;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.DecisionType;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

import com.google.common.base.Objects;
import com.google.common.collect.Iterables;

import edu.kit.ipd.sdq.kamp4attack.core.BlackboardWrapper;
import edu.kit.ipd.sdq.kamp4attack.core.changepropagation.attackhandlers.AssemblyContextHandler;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

public class AssemblyContextContext extends AssemblyContextHandler {

	public AssemblyContextContext(final BlackboardWrapper modelStorage, final DataHandlerAttacker dataHandler) {
		super(modelStorage, dataHandler);
	}

	private AssemblyContextDetail assemblyDetail;

	@Override
	protected Optional<CompromisedAssembly> attackComponent(final AssemblyContext component,
			final CredentialChange change, final EObject source, Attacker attacker) {
		final List<? extends UsageSpecification> credentials = this.getCredentials(change);

		final var result = this.queryAccessForEntity(component, credentials);

		AssemblyContextDetail detail = AttackerFactory.eINSTANCE.createAssemblyContextDetail();
		detail.setEntityName(assemblyDetail.getEntityName());
		detail.getCompromisedComponents().add(component);
//		if (component.getEntityName() != assemblyDetail.getEntityName()) {
//			detail.getCompromisedComponents().add(component);
//		}
		System.out.println("+++" + detail.getCompromisedComponents().stream().map(AssemblyContext::getEntityName)
				.collect(Collectors.toList()));

		if (result.isPresent() && Objects.equal(result.get().getDecision(), DecisionType.PERMIT)) {
			final var sourceList = this.createSource(source, credentials);
			final var compromised = HelperCreationCompromisedElements.createCompromisedAssembly(component,
					AssemblyHelper.getAssemblyContextDetail(component), sourceList);
			System.out.println(AssemblyHelper.getAssemblyContextDetail(component).getCompromisedComponents().stream()
					.map(AssemblyContext::getEntityName).collect(Collectors.toList()));
			// Endlosschleife
			return Optional.of(compromised);
		}
		return Optional.empty();
	}

	@Override
	protected Optional<CompromisedAssembly> attackComponent(AssemblyContextDetail component, CredentialChange change,
			EObject source, Attacker attacker) {
		this.assemblyDetail = component;
		for (AssemblyContext assembly : component.getCompromisedComponents()) {
			Optional<CompromisedAssembly> compromisedAssembly = this.attackComponent(assembly, change, source,
					attacker);
			if (compromisedAssembly.isPresent()) {
				return compromisedAssembly;
			}
		}
		return Optional.empty();
	}

}
