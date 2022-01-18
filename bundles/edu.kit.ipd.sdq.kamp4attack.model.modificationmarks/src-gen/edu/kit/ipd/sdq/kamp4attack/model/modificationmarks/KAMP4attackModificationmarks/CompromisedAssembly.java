/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

/**
 * <!-- begin-user-doc -->
 * A representation of the model object '<em><b>Compromised Assembly</b></em>'.
 * <!-- end-user-doc -->
 *
 * <p>
 * The following features are supported:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly#getAffectedAssembly <em>Affected Assembly</em>}</li>
 * </ul>
 *
 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCompromisedAssembly()
 * @model
 * @generated
 */
public interface CompromisedAssembly extends ModifyEntity<AssemblyContextDetail> {
	/**
	 * Returns the value of the '<em><b>Affected Assembly</b></em>' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @return the value of the '<em>Affected Assembly</em>' reference.
	 * @see #setAffectedAssembly(AssemblyContext)
	 * @see edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage#getCompromisedAssembly_AffectedAssembly()
	 * @model required="true"
	 * @generated
	 */
	AssemblyContext getAffectedAssembly();

	/**
	 * Sets the value of the '{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly#getAffectedAssembly <em>Affected Assembly</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @param value the new value of the '<em>Affected Assembly</em>' reference.
	 * @see #getAffectedAssembly()
	 * @generated
	 */
	void setAffectedAssembly(AssemblyContext value);

} // CompromisedAssembly
