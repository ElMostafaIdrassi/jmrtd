package org.jmrtd.test.lds;

import java.util.logging.Logger;

import org.jmrtd.lds.ICAOCountry;

import junit.framework.TestCase;
import net.sf.scuba.data.Country;
import net.sf.scuba.data.ISOCountry;
import net.sf.scuba.data.UnicodeCountry;

public class CountryTest extends TestCase {

	private static final Logger LOGGER = Logger.getLogger("org.jmrtd");
	
	public void testCountryValues() {
		Country[] values = Country.values();
		assertNotNull(values);
		for (Country country: values) {
			// LOGGER.info("DEBUG: country = " + country);
		}
	}

	public void testGermany() {
		Country icaoGermany = ICAOCountry.getInstance("D<<");
		Country isoGermany = Country.getInstance("DEU");
		assertNotNull(icaoGermany);
		assertTrue(ISOCountry.DE == isoGermany || UnicodeCountry.DE == isoGermany);
		assertTrue(ISOCountry.DE.equals(isoGermany) || UnicodeCountry.DE.equals(isoGermany));
		assertEquals(ICAOCountry.DE, icaoGermany);
		assertSame(ICAOCountry.DE, icaoGermany);
		assertEquals(isoGermany.toAlpha2Code(), icaoGermany.toAlpha2Code());
	}

	public void testTaiwan() {
		Country icaoCountry = ICAOCountry.getInstance("TWN");
		assertNotNull(icaoCountry);
		Country unicodeCountry = Country.getInstance("TWN");
		assertNotNull(unicodeCountry);
		assertEquals(icaoCountry, unicodeCountry);
		assertFalse(icaoCountry.getName().toLowerCase().contains("china"));
	}
	
	public void testNetherlands() {
		assertTrue(Country.getInstance("NLD") == ISOCountry.NL || Country.getInstance("NLD") == UnicodeCountry.NL);
		assertTrue(ISOCountry.NL.equals(Country.getInstance("NLD")) || UnicodeCountry.NL.equals(Country.getInstance("NLD")));
		assertEquals(ISOCountry.NL.getName(), UnicodeCountry.NL.getName());
	}

	public void testUtopia() {
		Country utopia = Country.getInstance("UT");
		assertNotNull(utopia);
		Country alsoUtopia = Country.getInstance("UTO");
		assertNotNull(alsoUtopia);
		assertEquals(alsoUtopia, utopia);
	}
}
