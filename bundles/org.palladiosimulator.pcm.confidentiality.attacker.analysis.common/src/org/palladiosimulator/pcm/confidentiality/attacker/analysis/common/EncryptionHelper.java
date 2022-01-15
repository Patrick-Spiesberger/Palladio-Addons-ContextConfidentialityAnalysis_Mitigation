package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.LinkedList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;

public class EncryptionHelper {
	
	/**
	 * Checks whether a component is encrypted and crackable. 
	 * In the event that the encryption level is low, the attacker's ability to crack the 
	 * encryption is checked. Secure encryption (level is high) is considered unbreakable
	 * @param component : Component which should be checked for crackability
	 * @param attacks : List of attacks that an attacker can carry out
	 */
	public static Boolean isCrackable(PCMElement component, final List<Attack> attacks) {		
		switch (component.getEncryptionLevel()) {
		case NONE:
			return true;
		case LOW:
			List<PCMElement> crackableComponents = new LinkedList<>();
			for (Attack attack : attacks) {
				crackableComponents.addAll(attack.getCrackableEncryptedComponents());
			}
			return crackableComponents.contains(component);
		case HIGH:
			return false;
		default:
			return false; //Exception bauen
		}
	}

}
