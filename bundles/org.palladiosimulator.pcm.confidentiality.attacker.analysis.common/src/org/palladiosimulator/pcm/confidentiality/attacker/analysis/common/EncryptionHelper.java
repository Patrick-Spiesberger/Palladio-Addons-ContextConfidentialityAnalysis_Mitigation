package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.List;
import java.util.stream.Collectors;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Encryption;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.EncryptionLevel;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Mitigation;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MitigationSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PreventLevel;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.Prevention;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

/**
 * This class is responsible for handling the crackability of an entire element.
 * 
 * @author patrick
 *
 */
public class EncryptionHelper {

	/**
	 * Checks whether a component is crackable. In the event that the prevention
	 * level is low, the attacker's ability to crack the encryption is checked.
	 * Secure components (level always) is considered unbreakable
	 * 
	 * @param component : Component which should be checked for crackability
	 * @param attacks   : List of attacks that an attacker can carry out
	 */
	public static Boolean isCrackable(PCMElement component, final List<Attack> attacks, Attacker attacker) {
		Mitigation mitigation = component.getMitigation();
		if (mitigation == null) { // no mitigation defined
			return true;
		}
		List<Prevention> preventions = filterPrevention(mitigation.getMitigationspecification());
		List<UsageSpecification> credentials = attacker.getCredentials();
		ListOperations listHelper = new ListOperations();
		boolean crackable = false;

		for (Prevention prevention : preventions) {
			if (prevention.getPreventionLevel() == PreventLevel.NEVER) {
				return true;
			}
		}

		for (Prevention prevention : preventions) {
			for (List<UsageSpecification> credential : listHelper.calculateLists(credentials, attacker,
					prevention.getNecessaryCredentials().size())) {
				if (prevention.getPreventionLevel() == PreventLevel.SOMETIMES) {
					crackable = checkCredentials(credential, prevention.getNecessaryCredentials());
					if (crackable) { // At least one measure could be cracked
						return true;
					}

				}
			}
		}
		return crackable;
	}

	public static Boolean isCrackable(DatamodelAttacker data, Attacker attacker) {
		Mitigation mitigation = data.getMitigation();
		if (mitigation == null) { // no mitigation defined
			return true;
		}
		List<Encryption> encryptions = filterEncryption(mitigation.getMitigationspecification());
		List<UsageSpecification> credentials = attacker.getCredentials();
		ListOperations listHelper = new ListOperations();
		boolean crackable = false;

		for (Encryption encryption : encryptions) {
			if (encryption.getEncryptionLevel() == EncryptionLevel.NONE) {
				return true;
			}
		}

		for (Encryption encryption : encryptions) {
			for (List<UsageSpecification> credential : listHelper.calculateLists(credentials, attacker,
					encryption.getNecessaryCredentials().size())) {
				if (encryption.getEncryptionLevel() == EncryptionLevel.LOW) {
					crackable = checkCredentials(credential, encryption.getNecessaryCredentials());
					if (crackable) { // At least one measure could be cracked
						return true;
					}
				}
				if (attacker.getDataDecyptionKeyBag().contains(data.getRequiredDecryptionKey())) {
					return true;
				}

			}
		}
		return crackable;

	}

	private static List<Prevention> filterPrevention(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(e -> (e instanceof Prevention)).map(e -> ((Prevention) e))
				.collect(Collectors.toList());
	}

	private static List<Encryption> filterEncryption(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(e -> (e instanceof Encryption)).map(e -> ((Encryption) e))
				.collect(Collectors.toList());
	}

	private static boolean checkCredentials(List<UsageSpecification> actualCredentials,
			List<UsageSpecification> requiredCredentials) {
		for (UsageSpecification credential : requiredCredentials) {
			if (actualCredentials.contains(credential)) {
				return false;
			}
		}
		return true;
	}
}
