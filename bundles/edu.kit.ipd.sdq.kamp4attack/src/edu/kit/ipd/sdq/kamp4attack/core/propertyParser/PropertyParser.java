package edu.kit.ipd.sdq.kamp4attack.core.propertyParser;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * This class is responsible for reading out and handling property files
 * 
 * @author Patrick Spiesberger
 * @version 1.0
 *
 */
public class PropertyParser {

	// context selection
	private boolean missingAttributesEnabled = false;

	// general
	private int[] timeLimit = {0, 0, 0, 12, 0, 0}; //years, months, days, hours, minutes, seconds

	private InputStream input;

	private boolean validInput = true;

	Properties prop = new Properties();

	public PropertyParser(String path) {
		try {
			this.input = new FileInputStream(path);
			try {
				prop.load(input);
				loadValues();
			} catch (IOException e) {
				validInput = false;
				java.lang.System.out.println("The requested file " + path + " cannot be read.");
			}
		} catch (FileNotFoundException e) {
			validInput = false;
			java.lang.System.out.println("The specified path  " + path + " does not exist.");
		}
	}

	private void loadValues() {
		if (validInput) {
			try {
				this.missingAttributesEnabled = Boolean.valueOf(prop.getProperty("missingAttributesEnabled"));
			} catch (Exception e) {
				e.printStackTrace();
			}

			String[] separatedStrings = prop.getProperty("timeLimit").replaceAll("\\[", "").replaceAll("]", "")
					.split(",");
			for (int i = 0; i < separatedStrings.length; i++) {
				try {
					this.timeLimit[i] = Integer.parseInt(separatedStrings[i]);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}

	public boolean isMissingAttributesEnabled() {
		return missingAttributesEnabled;
	}

	public int[] getTimeLimit() {
		return timeLimit;
	}
}