/**
 */
package edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl;

import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.CompromisedAssembly;
import edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.KAMP4attackModificationmarksPackage;

import org.eclipse.emf.common.notify.Notification;

import org.eclipse.emf.ecore.EClass;
import org.eclipse.emf.ecore.InternalEObject;

import org.eclipse.emf.ecore.impl.ENotificationImpl;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;

import org.palladiosimulator.pcm.core.composition.AssemblyContext;

/**
 * <!-- begin-user-doc -->
 * An implementation of the model object '<em><b>Compromised Assembly</b></em>'.
 * <!-- end-user-doc -->
 * <p>
 * The following features are implemented:
 * </p>
 * <ul>
 *   <li>{@link edu.kit.ipd.sdq.kamp4attack.model.modificationmarks.KAMP4attackModificationmarks.impl.CompromisedAssemblyImpl#getAffectedAssembly <em>Affected Assembly</em>}</li>
 * </ul>
 *
 * @generated
 */
public class CompromisedAssemblyImpl extends ModifyEntityImpl<AssemblyContextDetail> implements CompromisedAssembly {
	/**
	 * The cached value of the '{@link #getAffectedAssembly() <em>Affected Assembly</em>}' reference.
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @see #getAffectedAssembly()
	 * @generated
	 * @ordered
	 */
	protected AssemblyContext affectedAssembly;

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	protected CompromisedAssemblyImpl() {
		super();
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	protected EClass eStaticClass() {
		return KAMP4attackModificationmarksPackage.Literals.COMPROMISED_ASSEMBLY;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public AssemblyContext getAffectedAssembly() {
		if (affectedAssembly != null && affectedAssembly.eIsProxy()) {
			InternalEObject oldAffectedAssembly = (InternalEObject)affectedAssembly;
			affectedAssembly = (AssemblyContext)eResolveProxy(oldAffectedAssembly);
			if (affectedAssembly != oldAffectedAssembly) {
				if (eNotificationRequired())
					eNotify(new ENotificationImpl(this, Notification.RESOLVE, KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY, oldAffectedAssembly, affectedAssembly));
			}
		}
		return affectedAssembly;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public AssemblyContext basicGetAffectedAssembly() {
		return affectedAssembly;
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	public void setAffectedAssembly(AssemblyContext newAffectedAssembly) {
		AssemblyContext oldAffectedAssembly = affectedAssembly;
		affectedAssembly = newAffectedAssembly;
		if (eNotificationRequired())
			eNotify(new ENotificationImpl(this, Notification.SET, KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY, oldAffectedAssembly, affectedAssembly));
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public Object eGet(int featureID, boolean resolve, boolean coreType) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY:
				if (resolve) return getAffectedAssembly();
				return basicGetAffectedAssembly();
		}
		return super.eGet(featureID, resolve, coreType);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eSet(int featureID, Object newValue) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY:
				setAffectedAssembly((AssemblyContext)newValue);
				return;
		}
		super.eSet(featureID, newValue);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public void eUnset(int featureID) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY:
				setAffectedAssembly((AssemblyContext)null);
				return;
		}
		super.eUnset(featureID);
	}

	/**
	 * <!-- begin-user-doc -->
	 * <!-- end-user-doc -->
	 * @generated
	 */
	@Override
	public boolean eIsSet(int featureID) {
		switch (featureID) {
			case KAMP4attackModificationmarksPackage.COMPROMISED_ASSEMBLY__AFFECTED_ASSEMBLY:
				return affectedAssembly != null;
		}
		return super.eIsSet(featureID);
	}

} //CompromisedAssemblyImpl
