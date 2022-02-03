package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.LinkedList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;

/**
 * This class is responsible for handling the crackability of an entire element.
 * 
 * @author patrick
 *
 */
public class EncryptionHelper {

	/**
	 * Checks whether a component is crackable. In the event that the
	 * prevention level is low, the attacker's ability to crack the encryption is
	 * checked. Secure components (level always) is considered unbreakable
	 * 
	 * @param component : Component which should be checked for crackability
	 * @param attacks   : List of attacks that an attacker can carry out
	 */
	public static Boolean isCrackable(PCMElement component, final List<Attack> attacks) {
		switch (component.getElementCanPreventAttackPath()) {
		case NEVER:
			return true;
		case SOMETIMES:
			List<PCMElement> crackableComponents = new LinkedList<>();
			for (Attack attack : attacks) {
				crackableComponents.addAll(attack.getCrackableEncryptedComponents());
			}
			return crackableComponents.contains(component);
		case ALWAYS:
			return false;
		default:
			return true;
		}
	}
	
	public static Boolean isCrackable(DatamodelAttacker data, Attacker attacker) {
		switch (data.getEncryptionLevel()) {
		case NONE:
			return true;
		case LOW:
			List<String> availableKeys = attacker.getDataDecyptionKeyBag();
			return availableKeys.contains(data.getRequiredDecryptionKey());
		case HIGH:
			return false;
		default:
			return true;
		}
	}

}
