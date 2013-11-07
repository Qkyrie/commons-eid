/*
 * Commons eID Project.
 * Copyright (C) 2008-2012 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package com.trust1t.android.sdk.eid.core.files;



import com.trust1t.android.sdk.eid.core.tlv.OriginalData;
import com.trust1t.android.sdk.eid.core.tlv.TlvField;

/**
 * Holds all the fields within the eID address file. The nationality can be
 * found in the eID identity file.
 * 
 * @author Frank Cornelis
 * @see Identity
 *
 */
public class Address {

	/*
	 * We implement serializable to allow this class to be used in distributed
	 * containers as defined in the Servlet v2.4 specification.
	 */

	private static final long serialVersionUID = 1L;

	@TlvField(1)
	public String streetAndNumber;

	@TlvField(2)
	public String zip;

	@TlvField(3)
	public String municipality;

	@OriginalData
	public byte[] data;

	public String getStreetAndNumber() {
		return this.streetAndNumber;
	}

	public String getZip() {
		return this.zip;
	}

	public String getMunicipality() {
		return this.municipality;
	}

	public byte[] getData() {
		return this.data;
	}
}
