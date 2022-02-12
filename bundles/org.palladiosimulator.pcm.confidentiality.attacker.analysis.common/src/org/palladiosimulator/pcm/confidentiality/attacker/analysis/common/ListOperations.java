package org.palladiosimulator.pcm.confidentiality.attacker.analysis.common;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.palladiosimulator.pcm.confidentiality.attackerSpecification.Attacker;
import org.palladiosimulator.pcm.confidentiality.attackerSpecification.ListOperationEffort;
import org.palladiosimulator.pcm.confidentiality.context.system.UsageSpecification;

import com.google.common.collect.Lists;

/**
 * This class is responsible for the list operations related to access control
 * 
 * @author Patrick Spiesberger
 * @version 1.0
 *
 */
public class ListOperations {

	/**
	 * Generates a list of all combinations of certain length
	 */
	private void helper(List<int[]> combinations, int data[], int start, int end, int index) {
		if (index == data.length) {
			int[] combination = data.clone();
			combinations.add(combination);
		} else {
			int max = Math.min(end, end + 1 - data.length + index);
			for (int i = start; i <= max; i++) {
				data[index] = i;
				helper(combinations, data, i + 1, end, index + 1);
			}
		}
	}

	private List<int[]> generate(int n, int r) {
		List<int[]> combinations = new ArrayList<>();
		helper(combinations, new int[r], 0, n - 1, 0);
		return combinations;
	}

	/**
	 * Returns a specific item from a selected list
	 * 
	 * @param elements  : list of elements
	 * @param partList  : number of sublist
	 * @param elementAt : position of element in sublist
	 * @return : specific element
	 */
	public UsageSpecification getElement(List<List<UsageSpecification>> elements, int partList, int elementAt) {
		return elements.get(partList).get(elementAt);
	}

	/**
	 * Called up if desired by the user or if the maximum runtime has been exceeded.
	 * This method returns a partial list of combinations, assuming all elements in
	 * the list are of fixed length. This length is calculated alternately
	 * 
	 * @param elements : list of UsageSpecifications
	 * @return : partial list of certain length
	 */
	private List<List<UsageSpecification>> calculateAdvancedList(List<UsageSpecification> elements, int size) {
		List<int[]> combinations = generate(elements.size(), size);
		List<List<UsageSpecification>> returnList = new ArrayList<>();
		for (int[] combination : combinations) {
			List<UsageSpecification> elementPartList = new ArrayList<>();
			for (int index : combination) {
				elementPartList.add(elements.get(index));
			}
			returnList.add(elementPartList);
		}
		return Lists.reverse(returnList);
	}

	/**
	 * Decide which algorithm is used to select the partial lists (improvement of
	 * the runtime)
	 * 
	 * @param elements : list of elements
	 * @return : List of sublists
	 */
	public List<List<UsageSpecification>> calculateLists(List<UsageSpecification> elements, Attacker attacker,
			int size) {

		if (attacker.getContextSelectionListEffort() == ListOperationEffort.NONE) {
			List<List<UsageSpecification>> basicList = new LinkedList<>();
			basicList.add(elements);
			return basicList;
		}
		return calculateAdvancedList(elements, size);

	}

	protected final void prettyPrint(List<UsageSpecification> creds) {
		for (UsageSpecification cred : creds) {
			System.out.println("[" + cred.getEntityName() + " with ID " + cred.getId() + " and Attribut "
					+ cred.getAttribute().getEntityName() + "]");
		}
	}
}
