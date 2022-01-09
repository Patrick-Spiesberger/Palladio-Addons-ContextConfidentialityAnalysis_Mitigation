package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;

public class EncryptionHelper {
	
	public static Boolean isCrackable(PCMElement component) {
		switch (component.getEncryptionLevel()) {
		case NONE:
			return true;
		case LOW:
			//TODO: Anschauen ob eine Modellierung dieser Stufe im Angreifermodell sinnvoll ist
			return false;
		case HIGH:
			return false;
		default:
			return false;
		}
	}

}
