package edu.kit.ipd.sdq.kamp4attack.core.contextSelection;

import java.util.ArrayList;
import java.util.Collections;
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

	private int runningTimes;
	private boolean returnedAllElements = false;
	private int timeLimits[] = { 0, 0, 0, 12, 0, 0 }; // {years, months, days, hours, minutes, seconds}
	private double timePerCheck = 1.0;
	private boolean alternating = false;

	/**
	 * Constructor of ListOperations
	 */
	public ListOperations() {
		runningTimes = 0;
	}

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
	 * Generates a list of all sublists
	 * 
	 * @param data : list to be subdivided
	 * @return : list of partial length
	 */
	private List<List<UsageSpecification>> getCombinationsAll(List<UsageSpecification> data) {
		List<List<UsageSpecification>> combinations = new ArrayList<List<UsageSpecification>>();
		for (int i = 0; i < Math.pow(2, data.size()); i++) {
			List<UsageSpecification> element = new ArrayList<UsageSpecification>();
			for (int elem = 0; elem < data.size(); elem++) {
				if ((i & (int) Math.pow(2, elem)) > 0) {
					element.add(data.get(elem));
				}
			}
			combinations.add(element);
		}
		return Lists.reverse(combinations);
	}

	public List<List<Integer>> getCombinationsAllTest(List<Integer> data) {
		List<List<Integer>> combinations = new ArrayList<List<Integer>>();
		for (int i = 0; i < Math.pow(2, data.size()); i++) {
			List<Integer> element = new ArrayList<Integer>();
			for (int elem = 0; elem < data.size(); elem++) {
				if ((i & (int) Math.pow(2, elem)) > 0) {
					element.add(data.get(elem));
				}
			}
			combinations.add(element);
		}
		return Lists.reverse(combinations);
	}

	/**
	 * Calculates the number of combinations. This number is multiplied by an
	 * estimated duration of an individual analysis, which results in the
	 * approximate total runtime
	 * 
	 * @param elementSize    : number of elements in a list
	 * @param timePerElement : runtime of an analysis in seconds
	 * @return : estimated runtime [years, months, days, hours, minutes, seconds]
	 */
	public int[] calculateTime(int elementSize, double timePerElement) {
		int options = (int) Math.pow(2, elementSize);
		int timePerOption = (int) (options * timePerElement);
		int time[] = new int[6];
		time[0] = timePerOption / 31536000; // years
		time[1] = (timePerOption % 31536000) / 2628000; // months
		time[2] = (timePerOption % 2628000) / 86400; // days
		time[3] = (timePerOption % 86400) / 3600; // hours
		time[4] = (timePerOption % 3600) / 60; // minutes
		time[5] = (timePerOption % 60); // seconds
		return time;
	}

	/**
	 * Converts a number of seconds into an array of common units of time
	 * 
	 * @param seconds
	 * @return : max runtime [years, months, days, hours, minutes, seconds]
	 */
	private int[] calcTimeArray(int seconds) {
		int time[] = new int[6];
		time[0] = seconds / 31536000; // years
		time[1] = (seconds % 31536000) / 2628000; // months
		time[2] = (seconds % 2628000) / 86400; // days
		time[3] = (seconds % 86400) / 3600; // hours
		time[4] = (seconds % 3600) / 60; // minutes
		time[5] = (seconds % 60); // seconds
		return time;
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
	private List<List<UsageSpecification>> calculateAdvancedList(List<UsageSpecification> elements) {
		if (!(runningTimes + 1 > elements.size())) {
			// Returns elements according to their length
			List<int[]> combinations = generate(elements.size(), listLengthCalc(elements.size()));
			List<List<UsageSpecification>> returnList = new ArrayList<>();
			for (int[] combination : combinations) {
				List<UsageSpecification> elementPartList = new ArrayList<>();
				for (int index : combination) {
					elementPartList.add(elements.get(index));
				}
				returnList.add(elementPartList);
			}
			returnedAllElements = false;
			return Lists.reverse(returnList);
		} else {
			returnedAllElements = true;
			return Collections.emptyList();
		}
	}

	/**
	 * Calculates all combinations of a list
	 * @param elements : list of UsageSpecification
	 * @return : list of all combinations
	 */
	public List<List<UsageSpecification>> calculateSimpleList(List<UsageSpecification> elements) {
		returnedAllElements = true;
		return getCombinationsAll(elements);
	}

	/**
	 * Decide which algorithm is used to select the partial lists (improvement of
	 * the runtime)
	 * 
	 * @param elements : list of elements
	 * @return : List of sublists
	 */
	public List<List<UsageSpecification>> calculateLists(List<UsageSpecification> elements, Attacker attacker) {

		if (attacker.getContextSelectionListEffort() == ListOperationEffort.NONE) {
			List<List<UsageSpecification>> basicList = new LinkedList<>();
			basicList.add(elements);
			returnedAllElements = true;
			return basicList;
		}

		timeLimits = calcTimeArray(attacker.getContextSelectionMaxTime());
		// checks the estimated running time
		boolean overTime = false;
		for (int i = 0; i < timeLimits.length; i++) {
			if (calculateTime(elements.size(), timePerCheck)[i] > timeLimits[i]) {
				overTime = true;
			}
			if (timeLimits[i] != 0) {
				break;
			}
		}

		switch (attacker.getContextSelectionListEffort()) {
		case NONE:
			List<List<UsageSpecification>> basicList = new LinkedList<>();
			basicList.add(elements);
			returnedAllElements = true;
			return basicList;
		case STANDARD:
			if (overTime) {
				return calculateAdvancedList(elements);
			} else {
				return calculateSimpleList(elements);
			}
		case ALL:
			return calculateSimpleList(elements);
		case PART:
			return calculateAdvancedList(elements);
		default:
			System.out.println("Please check the UsageSpecification. The attacker can not perform some ListOperations");
			returnedAllElements = true;
			return Collections.emptyList();
		}

	}

	/**
	 * According to optimization, some lists are more efficient to generate and
	 * evaluate than others. This method calculates the length of the most
	 * efficiently evaluated lists for runtime optimization
	 * 
	 * @param lengthList : length of data-list
	 * @return : alternating sequence of numbers
	 */
	private int listLengthCalc(int lengthList) {
		if (!alternating) {
			alternating = !alternating;
			return runningTimes;
		} else {
			alternating = !alternating;
			int value = lengthList - runningTimes;
			runningTimes++;
			return value;
		}
	}

	/**
	 * Returns whether all sublists are returned. True = all parts lists were
	 * returned False = a selection of partial lists was returned A re-execution
	 * will return new sublists
	 * 
	 * @return : status of return values
	 */
	public Boolean returnedAllElements() {
		return returnedAllElements;
	}
	
	protected final void prettyPrint(List<UsageSpecification> creds) {
		for (UsageSpecification cred : creds) {
			System.out.println("[" + cred.getEntityName() + " with ID " + cred.getId() + " and Attribut "
					+ cred.getAttribute().getEntityName() + "]");
		}
	}
}
