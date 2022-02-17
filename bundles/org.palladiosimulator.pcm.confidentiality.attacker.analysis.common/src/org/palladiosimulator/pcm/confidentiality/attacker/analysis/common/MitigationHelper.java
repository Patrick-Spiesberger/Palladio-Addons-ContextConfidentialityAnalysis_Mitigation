package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Encryption;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Mitigation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MitigationSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Privileges;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.Prevention;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;
import org.palladiosimulator.pcm.confidentiality.context.xacml.pdp.result.PDPResult;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class is responsible for handling the crackability of an entire element.
 * 
 * @author patrick
 *
 */
public class MitigationHelper {

	/**
	 * Checks whether a protection mechanism exists that can protect a PCMElement
	 * from attacker propagation
	 * 
	 * @param component : concrete component
	 * @param attacks   : list of attacks
	 * @param change    : changes of credentials
	 * @param attacker  : concrete attacker
	 * @return : True if the PCMElement has no protection mechanism or it can be
	 *         broken
	 */
	public static Boolean isCrackable(PCMElement component, final List<Attack> attacks, final CredentialChange change,
			final Attacker attacker) {
		Mitigation mitigation = component.getMitigation();
		if (mitigation == null) { // no mitigation defined
			return true;
		}
		for (Prevention specification : filterPrevention(mitigation.getMitigationspecification())) {
			Vulnerability vulnerability = VulnerabilityHelper.checkAttack(
					isAuthenticated(specification.getVulnerabilities()), specification.getVulnerabilities(),
					attacker.getAttacks(), AttackVector.LOCAL, null);
			if (vulnerability != null) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks whether there are concrete mechanisms for protecting the data
	 * (encryption) and whether these can be broken
	 */
	public static Boolean isCrackable(final DatamodelAttacker data, final CredentialChange change,
			final Attacker attacker) {
		Mitigation mitigation = data.getMitigation();
		if (mitigation == null) { // no mitigation defined
			return true;
		}
		for (Encryption specification : filterEncryption(mitigation.getMitigationspecification())) {
			Vulnerability vulnerability = VulnerabilityHelper.checkAttack(
					isAuthenticated(specification.getVulnerabilities()), specification.getVulnerabilities(),
					attacker.getAttacks(), AttackVector.LOCAL, null);
			if (vulnerability != null) {
				return true;
			}
		}
		if (attacker.getDataDecyptionKeyBag().contains(data.getRequiredDecryptionKey())) {
			return true;
		}
		return false;
	}

	private static List<Prevention> filterPrevention(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(e -> (e instanceof Prevention)).map(e -> ((Prevention) e))
				.collect(Collectors.toList());
	}

	private static List<Encryption> filterEncryption(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(e -> (e instanceof Encryption)).map(e -> ((Encryption) e))
				.collect(Collectors.toList());
	}

	private static List<UsageSpecification> getCredentials(final CredentialChange changes) {
		return changes.getContextchange().stream().map(ContextChange::getAffectedElement).collect(Collectors.toList());
	}

	private static boolean isAuthenticated(List<Vulnerability> vulnerabilityList) {
		// TODO: Auswertung der Ergebnisse
		return true;
	}

}
