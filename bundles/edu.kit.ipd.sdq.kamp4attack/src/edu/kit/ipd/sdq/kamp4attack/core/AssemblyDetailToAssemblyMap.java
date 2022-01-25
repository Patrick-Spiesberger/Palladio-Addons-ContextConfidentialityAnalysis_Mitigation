package edu.kit.ipd.sdq.kamp4attack.core;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AssemblyDetailToAssemblyMap {

	private AssemblyContext assemblyContext;
	private AssemblyContextDetail assemblyContextDetail;

	public AssemblyDetailToAssemblyMap(AssemblyContext assembly, AssemblyContextDetail assemblyDetail) {
		this.assemblyContext = assembly;
		this.assemblyContextDetail = assemblyDetail;
	}

	public AssemblyContext getAssemblyContext() {
		return assemblyContext;
	}

	public void setAssemblyContext(AssemblyContext assemblyContext) {
		this.assemblyContext = assemblyContext;
	}

	public AssemblyContextDetail getAssemblyContextDetail() {
		return assemblyContextDetail;
	}

	public void setAssemblyContextDetail(AssemblyContextDetail assemblyContextDetail) {
		this.assemblyContextDetail = assemblyContextDetail;
	}

	public boolean isSameElement(AssemblyContext assemblyContext, AssemblyContextDetail assemblyContextDetail) {
		return (assemblyContextDetail.getCompromisedComponents().size() == 1
				&& EcoreUtil.equals(assemblyContextDetail.getCompromisedComponents().get(0), assemblyContext));
	}
}
