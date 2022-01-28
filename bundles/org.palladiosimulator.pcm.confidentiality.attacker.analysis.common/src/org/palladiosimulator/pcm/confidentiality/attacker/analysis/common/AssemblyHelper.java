package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.LinkedList;
import java.util.List;

import org.eclipse.emf.ecore.util.EcoreUtil;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.AssemblyContextDetail;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.impl.AssemblyContextDetailImpl;
import org.palladiosimulator.pcm.core.composition.AssemblyContext;

public class AssemblyHelper {

	private static List<AssemblyToAssemblyDetailMap> allComponents = new LinkedList<>();

	public static List<AssemblyToAssemblyDetailMap> getAllComponents() {
		return allComponents;
	}

	public static void setAllComponents(List<AssemblyToAssemblyDetailMap> allComponents) {
		AssemblyHelper.allComponents = allComponents;
	}

	public static AssemblyToAssemblyDetailMap getMapAtIndex(int index) {
		return allComponents.get(index);
	}

	public static Boolean isInList(AssemblyContext component) {
		for (AssemblyToAssemblyDetailMap element : allComponents) {
			if (EcoreUtil.equals(element.getAssemblyContext(), component)) {
				return true;
			}
		}
		return true;
	}

	public static AssemblyContextDetail getAssemblyContextDetail(AssemblyContext component) {
		for (AssemblyToAssemblyDetailMap element : allComponents) {
			if (EcoreUtil.equals(element.getAssemblyContext(), component)) {
				return element.getAssemblyContextDetail();
			}
		}
		// should be unreachable code
		AssemblyContextDetail stub = new AssemblyContextDetailImpl();
		stub.getCompromisedComponents().add(component);
		stub.setEntityName(component.getEntityName());
		stub.setId(component.getId());
		allComponents.add(new AssemblyToAssemblyDetailMap(component, stub));
		return stub;
	}
}
