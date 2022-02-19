package edu.kit.ipd.sdq.kamp4attack.core.mitigation;

import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attacker.helper.VulnerabilityHelper;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.DatamodelAttacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Encryption;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.MitigationSpecification;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Attack;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.AttackVector;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.attackSpecification.Vulnerability;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.PCMElement;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.pcmIntegration.Prevention;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.ContextChange;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CredentialChange;

/**
 * This class is responsible for handling the crackability of an entire element.
 * 
 * @author Patrick Spiesberger
 *
 */
public class MitigationHelper {

	public MitigationHelper() {

	}

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
	public boolean isCrackable(PCMElement component, final List<Attack> attacks, final CredentialChange change) {
		if (component.getMitigation() == null) {
			return true;
		}
		List<MitigationSpecification> mitigation = component.getMitigation().getMitigationspecification();
		if (mitigation.size() == 0) { // no mitigation defined
			return true;
		}
		for (Prevention prevention : filterPrevention(mitigation)) {
			var vulnerability = VulnerabilityHelper.checkAttack(false, prevention.getVulnerabilities(), attacks,
					AttackVector.LOCAL, null);
			if (vulnerability != null) {
				if (mitigationIsBreakable(prevention.getNecessaryCredentials(),
						getCredentials(change, vulnerability))) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Checks whether there are concrete mechanisms for protecting the data
	 * (encryption) and whether these can be broken
	 */
	public boolean isCrackable(final DatamodelAttacker data, final List<Attack> attacks, final CredentialChange change) {
		if (data.getMitigation() == null) {
			return true;
		}
		List<MitigationSpecification> mitigation = data.getMitigation().getMitigationspecification();
		if (mitigation.size() == 0) { // no mitigation defined
			return true;
		}
		for (Encryption encryption : filterEncryption(mitigation)) {
			var vulnerability = VulnerabilityHelper.checkAttack(false, encryption.getVulnerabilities(),
					attacks, AttackVector.LOCAL, null);
			if (vulnerability != null) {
				if (mitigationIsBreakable(encryption.getNecessaryCredentials(),
						getCredentials(change, vulnerability))) {
					return true;
				}
			}
		}
		return false;
	}

	private List<Prevention> filterPrevention(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(Prevention.class::isInstance).map(Prevention.class::cast)
				.collect(Collectors.toList());
	}

	private List<Encryption> filterEncryption(List<MitigationSpecification> mitigation) {
		return mitigation.stream().filter(Encryption.class::isInstance).map(Encryption.class::cast)
				.collect(Collectors.toList());
	}

	private List<UsageSpecification> getCredentials(final CredentialChange changes, final Vulnerability vulnerabilty) {
		var permissions = changes.getContextchange().stream().map(ContextChange::getAffectedElement)
				.collect(Collectors.toList());
		permissions.addAll(vulnerabilty.getGainedAttributes());
		return permissions;
	}

	private boolean mitigationIsBreakable(List<UsageSpecification> requiredPermissions,
			List<UsageSpecification> permissions) {
		boolean contains = false;
		for (UsageSpecification specification : requiredPermissions) {
			for (UsageSpecification avaliableSpecification : permissions) {
				if (EcoreUtil.equals(specification, avaliableSpecification)) {
					contains = true;
				}
			}
			if (!contains) {
				return false;
			}
			contains = false;
		}
		return true;
	}
}
