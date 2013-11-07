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

package com.trust1t.android.sdk.eid.core.components;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

import com.precisebiometrics.android.mtk.api.smartcardio.ATR;
import com.precisebiometrics.android.mtk.api.smartcardio.Card;
import com.precisebiometrics.android.mtk.api.smartcardio.CardChannel;
import com.precisebiometrics.android.mtk.api.smartcardio.CardException;
import com.precisebiometrics.android.mtk.api.smartcardio.CardTerminal;
import com.precisebiometrics.android.mtk.api.smartcardio.CommandAPDU;
import com.precisebiometrics.android.mtk.api.smartcardio.ResponseAPDU;
import com.trust1t.android.sdk.eid.core.exceptions.ResponseAPDUException;
import com.trust1t.android.sdk.eid.core.files.PinResult;
import com.trust1t.android.sdk.eid.core.impl.CCID;
import com.trust1t.android.sdk.eid.core.impl.FileType;
import com.trust1t.android.sdk.eid.core.impl.LocaleManager;

/**
 * One BeIDCard instance represents one Belgian Electronic Identity Card,
 * physically present in a connected javax.smartcardio.CardTerminal. It exposes
 * the publicly accessible features of the BELPIC applet on the card's chip:
 * <ul>
 * <li>Reading Certificates and Certificate Chains
 * <li>Signing of digests non-repudiation and authentication purposes
 * <li>Verification and Alteration of the VERIFY_PIN code
 * <li>Reading random bytes from the on-board random generator
 * <li>Creating text message transaction signatures on specialized readers
 * <li>VERIFY_PIN unblocking using PUK codes
 * </ul>
 * <p>
 * BeIDCard instances rely on an instance of BeIDCardUI to support user
 * interaction, such as obtaining VERIFY_PIN and PUK codes for authentication,
 * signing, verifying, changing VERIFY_PIN codes, and for notifying the user of
 * the progress of such operations on a Secure Pinpad Device. A default
 * implementation is available as DefaultBeIDCardUI, and unless replaced by an
 * explicit call to setUI() will automatically be used (when present in the
 * class path).
 * <p>
 * BeIDCard instances automatically detect CCID features in the underlying
 * CardTerminal, and will choose the most secure path where several are
 * available, for example, when needing to acquire VERIFY_PIN codes from the
 * user, and the card is in a CCID-compliant Secure Pinpad Reader the VERIFY_PIN
 * entry features of the reader will be used instead of the corresponding
 * "obtain.." feature from the active BeIDCardUI. In that case, the
 * corresponding "advise.." method of the active BeIDCardUI will be called
 * instead, to advise the user to attend to the SPR.
 * <p>
 * To receive notifications of the progress of lengthy operations such as
 * reading 'files' (certificates, photo,..) or signing (which may be lengthy
 * because of user VERIFY_PIN interaction), register an instance of
 * BeIDCardListener using addCardListener(). This is useful, for example, for
 * providing progress indication to the user.
 * <p>
 * For detailed progress and error/debug logging, provide an instance of
 * be.fedict.commons.eid.spi.Logger to BeIDCard's constructor (the default
 * VoidLogger discards all logging and debug messages). You are advised to
 * provide some form of logging facility, for all but the most trivial
 * applications.
 * 
 * @author Frank Cornelis
 * @author Frank Marien
 * 
 */

public class BeIDCard {
	private static final String UI_MISSING_LOG_MESSAGE = "No BeIDCardUI set and can't load DefaultBeIDCardUI";
	private static final String UI_DEFAULT_REQUIRES_HEAD = "No BeIDCardUI set and DefaultBeIDCardUI requires a graphical environment";
	private static final String DEFAULT_UI_IMPLEMENTATION = "be.fedict.eid.commons.dialogs.DefaultBeIDCardUI";

	private static final byte[] BELPIC_AID = new byte[] { (byte) 0xA0, 0x00,
			0x00, 0x01, 0x77, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35, };
	private static final byte[] APPLET_AID = new byte[] { (byte) 0xA0, 0x00,
			0x00, 0x00, 0x30, 0x29, 0x05, 0x70, 0x00, (byte) 0xAD, 0x13, 0x10,
			0x01, 0x01, (byte) 0xFF, };
	private static final int BLOCK_SIZE = 0xff;

	private final CardChannel cardChannel;
	private final CertificateFactory certificateFactory;

	private final Card card;

	private CCID ccid;
	private CardTerminal cardTerminal;
	private Locale locale;

	/**
	 * Instantiate a BeIDCard from an already connected javax.smartcardio.Card,
	 * with a Logger implementation to receive logging output.
	 * 
	 * @param card
	 *            a javax.smartcardio.Card that you have previously determined
	 *            to be a BeID Card
	 * @throws IllegalArgumentException
	 *             when passed a null logger. to disable logging, call
	 *             BeIDCard(Card) instead.
	 * @throws RuntimeException
	 *             when no CertificateFactory capable of producing X509
	 *             Certificates is available.
	 */
	public BeIDCard(final Card card) {
		this.card = card;
		this.cardChannel = card.getBasicChannel();
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (final CertificateException e) {
			throw new RuntimeException("X.509 algo", e);
		}
	}

	/**
	 * close this BeIDCard, when you are done with it, to release any underlying
	 * resources. All subsequent calls will fail.
	 * 
	 * @return this BeIDCard instance, to allow method chaining
	 */
	public BeIDCard close() {
		setCardTerminal(null);

		try {
			this.card.disconnect(true);
		} catch (final CardException e) {
		}

		return this;
	}

	/**
	 * Reads a certain certificate from the card. Which certificate to read is
	 * determined by the FileType param. Applicable FileTypes are
	 * AuthentificationCertificate, NonRepudiationCertificate, CACertificate,
	 * RootCertificate and RRNCertificate.
	 * 
	 * @param fileType
	 * @return the certificate requested
	 * @throws java.security.cert.CertificateException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public X509Certificate getCertificate(final FileType fileType)
			throws CertificateException, CardException, IOException,
			InterruptedException {
		return (X509Certificate) this.certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						readFile(fileType)));
	}

	/**
	 * Returns the X509 authentication certificate. This is a convenience method
	 * for <code>getCertificate(FileType.AuthentificationCertificate)</code>
	 * 
	 * @return the X509 Authentication Certificate from the card.
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public X509Certificate getAuthenticationCertificate() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificate(FileType.AuthentificationCertificate);
	}

	/**
	 * Returns the X509 non-repudiation certificate. This is a convencience
	 * method for
	 * <code>getCertificate(FileType.NonRepudiationCertificate)</code>
	 * 
	 * @return
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public X509Certificate getSigningCertificate() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificate(FileType.NonRepudiationCertificate);
	}

	/**
	 * Returns the citizen CA certificate. This is a convenience method for
	 * <code>getCertificate(FileType.CACertificate)</code>
	 * 
	 * @return
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public X509Certificate getCACertificate() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificate(FileType.CACertificate);
	}

	/**
	 * Returns the Root CA certificate.
	 * 
	 * @return the Root CA X509 certificate.
	 * @throws java.security.cert.CertificateException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public X509Certificate getRootCACertificate() throws CertificateException,
			CardException, IOException, InterruptedException {
		return this.getCertificate(FileType.RootCertificate);
	}

	/**
	 * Returns the national registration certificate. This is a convencience
	 * method for <code>getCertificate(FileType.RRNCertificate)</code>
	 * 
	 * @return
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public X509Certificate getRRNCertificate() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificate(FileType.RRNCertificate);
	}

	/**
	 * Returns the entire certificate chain for a given file type. Of course,
	 * only file types corresponding with a certificate are accepted. Which
	 * certificate's chain to return is determined by the FileType param.
	 * Applicable FileTypes are AuthentificationCertificate,
	 * NonRepudiationCertificate, CACertificate, and RRNCertificate.
	 * 
	 * @param fileType
	 *            which certificate's chain to return
	 * @return the certificate's chain up to and including the Belgian Root Cert
	 * @throws java.security.cert.CertificateException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public List<X509Certificate> getCertificateChain(final FileType fileType)
			throws CertificateException, CardException, IOException,
			InterruptedException {
		final List<X509Certificate> chain = new LinkedList<X509Certificate>();
		chain.add((X509Certificate) this.certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						readFile(fileType))));
		if (fileType.chainIncludesCitizenCA()) {
			chain.add((X509Certificate) this.certificateFactory
					.generateCertificate(new ByteArrayInputStream(
							readFile(FileType.CACertificate))));
		}
		chain.add((X509Certificate) this.certificateFactory
				.generateCertificate(new ByteArrayInputStream(
						readFile(FileType.RootCertificate))));
		return chain;
	}

	/**
	 * Returns the X509 authentication certificate chain. (Authentication ->
	 * Citizen CA -> Root) This is a convenience method for
	 * <code>getCertificateChain(FileType.AuthentificationCertificate)</code>
	 * 
	 * @return the authentication certificate chain
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public List<X509Certificate> getAuthenticationCertificateChain()
			throws CardException, IOException, CertificateException,
			InterruptedException {
		return this.getCertificateChain(FileType.AuthentificationCertificate);
	}

	/**
	 * Returns the X509 non-repudiation certificate chain. (Non-Repudiation ->
	 * Citizen CA -> Root) This is a convenience method for
	 * <code>getCertificateChain(FileType.NonRepudiationCertificate)</code>
	 * 
	 * @return the non-repudiation certificate chain
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public List<X509Certificate> getSigningCertificateChain()
			throws CardException, IOException, CertificateException,
			InterruptedException {
		return this.getCertificateChain(FileType.NonRepudiationCertificate);
	}

	/**
	 * Returns the Citizen CA X509 certificate chain. (Citizen CA -> Root) This
	 * is a convenience method for
	 * <code>getCertificateChain(FileType.CACertificate)</code>
	 * 
	 * @return the citizen ca certificate chain
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public List<X509Certificate> getCACertificateChain() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificateChain(FileType.CACertificate);
	}

	/**
	 * Returns the national registry X509 certificate chain. (National Registry
	 * -> Root) This is a convenience method for
	 * <code>getCertificateChain(FileType.RRNCertificate)</code>
	 * 
	 * @return the national registry certificate chain
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws java.security.cert.CertificateException
	 * @throws InterruptedException
	 */
	public List<X509Certificate> getRRNCertificateChain() throws CardException,
			IOException, CertificateException, InterruptedException {
		return this.getCertificateChain(FileType.RRNCertificate);
	}

	/**
	 * Sign a given digest value.
	 * 
	 * @param digestValue
	 *            the digest value to be signed.
	 * @param digestAlgo
	 *            the algorithm used to calculate the given digest value.
	 * @param fileType
	 *            the certificate's file type.
	 * @return
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public byte[] sign(final byte[] digestValue, final BeIDDigest digestAlgo,
			final FileType fileType, char[] pin) throws CardException,
			IOException, InterruptedException {

		if (!fileType.isCertificateUserCanSignWith()) {
			throw new IllegalArgumentException(
					"Not a certificate that can be used for signing: "
							+ fileType.name());
		}

		this.beginExclusive();

		try {

			ResponseAPDU responseApdu = transmitCommand(
					BeIDCommandAPDU.SELECT_ALGORITHM_AND_PRIVATE_KEY,
					new byte[] { (byte) 0x04, // length
							// of
							// following
							// data
							(byte) 0x80, digestAlgo.getAlgorithmReference(), // algorithm
							// reference
							(byte) 0x84, fileType.getKeyId(), }); // private key
			// reference

			if (0x9000 != responseApdu.getSW()) {
				throw new ResponseAPDUException(
						"SET (select algorithm and private key) error",
						responseApdu);
			}

			if (FileType.NonRepudiationCertificate.getKeyId() == fileType
					.getKeyId()) {

				PinResult result = verifyPin(
						PINPurpose.NonRepudiationSignature, pin);

				if (!result.isSuccess()) {
					throw new CardException("Pincode is incorrect");
				}
			}

			final ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
			digestInfo.write(digestAlgo.getPrefix(digestValue.length));
			digestInfo.write(digestValue);
			responseApdu = transmitCommand(
					BeIDCommandAPDU.COMPUTE_DIGITAL_SIGNATURE,
					digestInfo.toByteArray());
			if (0x9000 == responseApdu.getSW()) {
				// If 9000 is the response we can just return our data
				return responseApdu.getData();
			}
			int sw = responseApdu.getSW();

			if (sw > 0x6100 && sw < 0x6200) {
				int length = sw - 0x6100;
				responseApdu = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00,
						length));
				if (responseApdu.getSW() == 0x9000) {
					return responseApdu.getData();
				} else {
					throw new ResponseAPDUException(
							"compute digital signature error", responseApdu);
				}
			}

			if (0x6982 != responseApdu.getSW()) {
				throw new ResponseAPDUException(
						"compute digital signature error", responseApdu);
			}

			PinResult result = verifyPin(PINPurpose.AuthenticationSignature,
					pin);

			responseApdu = transmitCommand(
					BeIDCommandAPDU.COMPUTE_DIGITAL_SIGNATURE,
					digestInfo.toByteArray());

			if (0x9000 == responseApdu.getSW()) {
				// If 9000 is the response we can just return our data
				return responseApdu.getData();
			}
			sw = responseApdu.getSW();

			if (sw > 0x6100 && sw < 0x6200) {
				int length = sw - 0x6100;
				responseApdu = transmit(new CommandAPDU(0x00, 0xC0, 0x00, 0x00,
						length));
				if (responseApdu.getSW() == 0x9000) {
					return responseApdu.getData();
				} else {
					throw new ResponseAPDUException(
							"compute digital signature error", responseApdu);
				}
			} else {
				throw new CardException("Reading failed");
			}

		} finally {
			this.endExclusive();
		}
	}

	/**
	 * Create an authentication signature.
	 * 
	 * @param toBeSigned
	 *            the data to be signed
	 * @return a SHA-1 digest of the input data signed by the citizen's
	 *         authentication key
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public byte[] signAuthn(final byte[] toBeSigned, String pin)
			throws NoSuchAlgorithmException, CardException, IOException,
			InterruptedException {

		return this.sign(toBeSigned, BeIDDigest.SHA_256,
				FileType.AuthentificationCertificate, pin.toCharArray());
	}

	/**
	 * Sign a given digest value.
	 * 
	 * @param digestValue
	 *            the digest value to be signed.
	 * @param digestAlgo
	 *            the algorithm used to calculate the given digest value.
	 * @param fileType
	 *            the certificate's file type.
	 * @param requireSecureReader
	 *            <code>true</code> if a secure pinpad reader is required.
	 * @return
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 * @throws be.fedict.commons.eid.client.spi.UserCancelledException
	 */
	// TODO: fix sign method
	/**
	 * public byte[] sign(final byte[] digestValue, final BeIDDigest digestAlgo,
	 * final be.fedict.commons.eid.client.FileType fileType, final boolean
	 * requireSecureReader) throws CardException, IOException,
	 * InterruptedException { if (!fileType.isCertificateUserCanSignWith()) {
	 * throw new IllegalArgumentException(
	 * "Not a certificate that can be used for signing: " + fileType.name()); }
	 * 
	 * if (getCCID().hasFeature(CCID.FEATURE.EID_PIN_PAD_READER)) { }
	 * 
	 * if (requireSecureReader &&
	 * (!getCCID().hasFeature(CCID.FEATURE.VERIFY_PIN_DIRECT)) &&
	 * (getCCID().hasFeature(CCID.FEATURE.VERIFY_PIN_START))) { throw new
	 * SecurityException("not a secure reader"); }
	 * 
	 * this.beginExclusive();
	 * 
	 * try { ResponseAPDU responseApdu = transmitCommand(
	 * BeIDCommandAPDU.SELECT_ALGORITHM_AND_PRIVATE_KEY, new byte[]{(byte) 0x04,
	 * // length // of // following // data (byte) 0x80,
	 * digestAlgo.getAlgorithmReference(), // algorithm // reference (byte)
	 * 0x84, fileType.getKeyId(),}); // private key // reference
	 * 
	 * if (0x9000 != responseApdu.getSW()) { throw new ResponseAPDUException(
	 * "SET (select algorithm and private key) error", responseApdu); }
	 * 
	 * if (be.fedict.commons.eid.client.FileType.NonRepudiationCertificate.
	 * getKeyId() == fileType .getKeyId()) { this.logger
	 * .debug("non-repudiation key detected, immediate VERIFY_PIN verify");
	 * verifyPin(PINPurpose.NonRepudiationSignature); }
	 * 
	 * final ByteArrayOutputStream digestInfo = new ByteArrayOutputStream();
	 * digestInfo.write(digestAlgo.getPrefix(digestValue.length));
	 * digestInfo.write(digestValue);
	 * 
	 * this.logger.debug("computing digital signature..."); responseApdu =
	 * transmitCommand( BeIDCommandAPDU.COMPUTE_DIGITAL_SIGNATURE, digestInfo
	 * .toByteArray()); if (0x9000 == responseApdu.getSW()) { /* OK, we could
	 * use the card VERIFY_PIN caching feature.
	 * 
	 * Notice that the card VERIFY_PIN caching also works when first doing an
	 * authentication after a non-repudiation signature.
	 */
	/**
	 * return responseApdu.getData(); } if (0x6982 != responseApdu.getSW()) {
	 * this.logger.debug("SW: " + Integer.toHexString(responseApdu.getSW()));
	 * throw new ResponseAPDUException( "compute digital signature error",
	 * responseApdu); } /* 0x6982 = Security constants not satisfied, so we do a
	 * VERIFY_PIN verification before retrying.
	 */
	/**
	 * this.logger.debug("VERIFY_PIN verification required...");
	 * verifyPin(PINPurpose.fromFileType(fileType));
	 * 
	 * this.logger .debug(
	 * "computing digital signature (attempt #2 after VERIFY_PIN verification)..."
	 * ); responseApdu = transmitCommand(
	 * BeIDCommandAPDU.COMPUTE_DIGITAL_SIGNATURE, digestInfo .toByteArray()); if
	 * (0x9000 != responseApdu.getSW()) { throw new ResponseAPDUException(
	 * "compute digital signature error", responseApdu); }
	 * 
	 * return responseApdu.getData(); } finally { this.endExclusive();
	 * notifySigningEnd(fileType);
	 * 
	 * } }
	 */

	/**
	 * Create an authentication signature.
	 * 
	 * @param toBeSigned
	 *            the data to be signed
	 * @param requireSecureReader
	 *            whether to require a secure pinpad reader to obtain the
	 *            citizen's VERIFY_PIN if false, the current BeIDCardUI will be
	 *            used in the absence of a secure pinpad reader. If true, an
	 *            exception will be thrown unless a SPR is available
	 * @return a SHA-1 digest of the input data signed by the citizen's
	 *         authentication key
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 * @throws be.fedict.commons.eid.client.spi.UserCancelledException
	 */
	/**
	 * public byte[] signAuthn(final byte[] toBeSigned, final boolean
	 * requireSecureReader) throws NoSuchAlgorithmException, CardException,
	 * IOException, InterruptedException { final MessageDigest messageDigest =
	 * BeIDDigest.SHA_1 .getMessageDigestInstance(); final byte[] digest =
	 * messageDigest.digest(toBeSigned); return this.sign(digest,
	 * BeIDDigest.SHA_1,
	 * be.fedict.commons.eid.client.FileType.AuthentificationCertificate,
	 * requireSecureReader); }
	 */

	/**
	 * Verifying VERIFY_PIN Code (without other actions, for testing
	 * VERIFY_PIN), using the most secure method available. Note that this still
	 * has the side effect of loading a successfully tests VERIFY_PIN into the
	 * VERIFY_PIN cache, so that unless the card is removed, a subsequent
	 * authentication attempt will not request the VERIFY_PIN, but proceed with
	 * the VERIFY_PIN given here.
	 * 
	 * @throws java.io.IOException
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws InterruptedException
	 * @throws be.fedict.commons.eid.client.spi.UserCancelledException
	 */
	/**
	 * public void verifyPin() throws IOException, CardException,
	 * InterruptedException { this.verifyPin(PINPurpose.PINTest); }
	 */
	// TODO: check what to do with pinpurpose...

	/**
	 * Returns random data generated by the eID card itself.
	 * 
	 * @param size
	 *            the size of the requested random data.
	 * @return size bytes of random data
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 */
	public byte[] getChallenge(final int size) throws CardException {
		final ResponseAPDU responseApdu = transmitCommand(
				BeIDCommandAPDU.GET_CHALLENGE, new byte[] {}, 0, 0, size);
		if (0x9000 != responseApdu.getSW()) {
			throw new ResponseAPDUException("get challenge failure: "
					+ Integer.toHexString(responseApdu.getSW()), responseApdu);
		}
		if (size != responseApdu.getData().length) {
			throw new RuntimeException("challenge size incorrect: "
					+ responseApdu.getData().length);
		}
		return responseApdu.getData();
	}

	/**
	 * Discard the citizen's VERIFY_PIN code from the VERIFY_PIN cache. Any
	 * subsequent Authentication signatures will require VERIFY_PIN entry.
	 * (non-repudation signatures are automatically protected)
	 * 
	 * @throws Exception
	 * @return this BeIDCard instance, to allow method chaining
	 */
	public BeIDCard logoff() throws Exception {
		final CommandAPDU logoffApdu = new CommandAPDU(0x80, 0xE6, 0x00, 0x00);
		final ResponseAPDU responseApdu = transmit(logoffApdu);
		if (0x9000 != responseApdu.getSW()) {
			throw new RuntimeException("logoff failed");
		}
		return this;
	}

	/**
	 * getATR returns the ATR of the eID Card. If this BeIDCard instance was
	 * constructed using the CardReader constructor, this is the only way to get
	 * to the ATR.
	 * 
	 * @return
	 */
	public ATR getATR() {
		return this.card.getATR();
	}

	/**
	 * @return the current Locale used in CCID SPR operations and UI
	 */
	public Locale getLocale() {
		if (this.locale != null) {
			return this.locale;
		}
		return LocaleManager.getLocale();
	}

	// ===========================================================================================================
	// low-level card operations
	// not recommended for general use.
	// if you find yourself having to call these, we'd very much like to hear
	// about it.
	// ===========================================================================================================

	/**
	 * Select the BELPIC applet on the chip. Since the BELPIC applet is supposed
	 * to be all alone on the chip, shouldn't be necessary.
	 * 
	 * @return this BeIDCard instance, to allow method chaining
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 */
	// TODO: handle exception handling
	public BeIDCard selectApplet() throws CardException {
		ResponseAPDU responseApdu;

		responseApdu = transmitCommand(BeIDCommandAPDU.SELECT_APPLET_0,
				BELPIC_AID);
		if (0x9000 != responseApdu.getSW()) {
			/*
			 * Try to select the Applet.
			 */
			try {
				responseApdu = transmitCommand(BeIDCommandAPDU.SELECT_APPLET_1,
						APPLET_AID);
			} catch (final CardException e) {
				return this;
			}
			if (0x9000 != responseApdu.getSW()) {
			} else {
			}
		} else {
		}

		return this;
	}

	// --------------------------------------------------------------------------------------------------------------------------------

	/**
	 * Begin an exclusive transaction with the card. Once this returns, only the
	 * calling thread will be able to access the card, until it calls
	 * endExclusive(). Other threads will receive a CardException. Use this when
	 * you need to make several calls to the card that depend on each other. for
	 * example, SELECT FILE and READ BINARY, or SELECT ALGORITHM and COMPUTE
	 * SIGNATURE, to avoid other threads/processes from interleaving commands
	 * that would break your transactional logic.
	 * 
	 * Called automatically by the higher-level methods in this class. If you
	 * end up calling this directly, this is either something wrong with your
	 * code, or with this class. Please let us know. You should really only have
	 * to be calling this when using some of the other low-level methods
	 * (transmitCommand, etc..) *never* in combination with the high-level
	 * methods.
	 * 
	 * @return this BeIDCard Instance, to allow method chaining.
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 */
	public BeIDCard beginExclusive() throws CardException {
		this.card.beginExclusive();
		return this;
	}

	/**
	 * Release an exclusive transaction with the card, started by
	 * beginExclusive().
	 * 
	 * @return this BeIDCard Instance, to allow method chaining.
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 */
	public BeIDCard endExclusive() throws CardException {
		this.card.endExclusive();
		return this;
	}

	// --------------------------------------------------------------------------------------------------------------------------------

	/**
	 * Read bytes from a previously selected "File" on the card. should be
	 * preceded by a call to selectFile so the card knows what you want to read.
	 * Consider using one of the higher-level methods, or readFile().
	 * 
	 * @param fileType
	 *            the file to read (to allow for notification)
	 * @param estimatedMaxSize
	 *            the estimated total size of the file to read (to allow for
	 *            notification)
	 * @return the data from the file
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public byte[] readBinary(final FileType fileType, final int estimatedMaxSize)
			throws CardException, IOException, InterruptedException {
		int offset = 0;
		final ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] data;
		int length = BLOCK_SIZE;
		boolean complete = false;
		while (true) {
			if (Thread.currentThread().isInterrupted()) {
				throw new InterruptedException();
			}
			final ResponseAPDU responseApdu = transmitCommand(
					BeIDCommandAPDU.READ_BINARY, offset >> 8, offset & 0xFF,
					length);
			final int sw = responseApdu.getSW();
			if (0x6B00 == sw) {
				// done should break
				break;
			}
			if (sw > 0x6000 && sw < 0x7000) {
				// implementing error handling for tactivo lezer
				length = sw - 0x6C00;
				if (length == 0xF4 || length == 0xB4 || length == 0x74
						|| length == 0x34) {
					tactivoFailureTempSolution(length, offset, baos);
					return baos.toByteArray();
				}
				data = responseApdu.getData();
			}

			else if (0x9000 != sw) {
				final IOException ioEx3 = new IOException(
						"BeIDCommandAPDU response error: "
								+ responseApdu.getSW());
				ioEx3.initCause(new ResponseAPDUException(responseApdu));
				throw ioEx3;
			} else if (0x9000 == sw) {
				data = responseApdu.getData();
				baos.write(data);
				offset += data.length;
				if (data.length != 255) {
					break;
				}
			}
		}
		return baos.toByteArray();
	}

	private ByteArrayOutputStream tactivoFailureTempSolution(int length,
			int offset, ByteArrayOutputStream baos) {
		byte[] data = null;

		try {
			final ResponseAPDU responseApdu = transmitCommand(
					BeIDCommandAPDU.READ_BINARY, offset >> 8, offset & 0xFF,
					length - 1);
			data = responseApdu.getData();
			offset += data.length;
			baos.write(data);
			final ResponseAPDU responseApdu2 = transmitCommand(
					BeIDCommandAPDU.READ_BINARY, offset >> 8, offset & 0xFF, 1);
			baos.write(responseApdu2.getData());
			return baos;
		} catch (CardException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Selects a file to read on the card
	 * 
	 * @param fileId
	 *            the file to read
	 * @return this BeIDCard Instance, to allow method chaining.
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.FileNotFoundException
	 */
	public BeIDCard selectFile(final byte[] fileId) throws CardException,
			FileNotFoundException {
		final ResponseAPDU responseApdu = transmitCommand(
				BeIDCommandAPDU.SELECT_FILE, fileId);
		if (0x9000 != responseApdu.getSW()) {
			final FileNotFoundException fnfEx = new FileNotFoundException(
					"wrong constants word after selecting file: "
							+ Integer.toHexString(responseApdu.getSW()));
			fnfEx.initCause(new ResponseAPDUException(responseApdu));
			throw fnfEx;
		}

		try {
			// SCARD_E_SHARING_VIOLATION fix
			Thread.sleep(20);
		} catch (final InterruptedException e) {
			throw new RuntimeException("sleep error: " + e.getMessage());
		}

		return this;
	}

	/**
	 * Reads a file from the card.
	 * 
	 * @param fileType
	 *            the file to read
	 * @return the data from the file
	 * @throws com.precisebiometrics.android.mtk.api.smartcardio.CardException
	 * @throws java.io.IOException
	 * @throws InterruptedException
	 */
	public byte[] readFile(final FileType fileType) throws CardException,
			IOException, InterruptedException {
		this.beginExclusive();
		try {
			this.selectFile(fileType.getFileId());
			return this.readBinary(fileType, fileType.getEstimatedMaxSize());
		} finally {
			this.endExclusive();
		}
	}

	// ===========================================================================================================
	// low-level card transmit commands
	// not recommended for general use.
	// if you find yourself having to call these, we'd very much like to hear
	// about it.
	// ===========================================================================================================

	protected byte[] transmitCCIDControl(final CCID.FEATURE feature)
			throws CardException {
		return transmitControlCommand(getCCID().getFeature(feature),
				new byte[0]);
	}

	protected byte[] transmitCCIDControl(final CCID.FEATURE feature,
			final byte[] command) throws CardException {
		return transmitControlCommand(getCCID().getFeature(feature), command);
	}

	protected byte[] transmitControlCommand(final int controlCode,
			final byte[] command) throws CardException {
		return this.card.transmitControlCommand(controlCode, command);
	}

	protected ResponseAPDU transmitCommand(final BeIDCommandAPDU apdu,
			final int p1, final int p2, final int le) throws CardException {
		return transmit(new CommandAPDU(apdu.getCla(), apdu.getIns(), p1, p2,
				le));
	}

	protected ResponseAPDU transmitCommand(final BeIDCommandAPDU apdu,
			final byte[] data) throws CardException {
		return transmit(new CommandAPDU(apdu.getCla(), apdu.getIns(),
				apdu.getP1(), apdu.getP2(), data));
	}

	protected ResponseAPDU transmitCommand(final BeIDCommandAPDU apdu,
			int length) throws CardException {
		return transmit(new CommandAPDU(apdu.getCla(), apdu.getIns(),
				apdu.getP1(), apdu.getP2(), length));
	}

	protected ResponseAPDU transmitCommand(final BeIDCommandAPDU apdu,
			final byte[] data, final int dataOffset, final int dataLength,
			final int ne) throws CardException {
		return transmit(new CommandAPDU(apdu.getCla(), apdu.getIns(),
				apdu.getP1(), apdu.getP2(), data, dataOffset, dataLength, ne));
	}

	private ResponseAPDU transmit(final CommandAPDU commandApdu)
			throws CardException {
		ResponseAPDU responseApdu = this.cardChannel.transmit(commandApdu);
		return responseApdu;
	}

	// TODO: add pin methods again

	public PinResult verifyPin(final PINPurpose purpose, char[] pin)
			throws IOException, CardException, InterruptedException {
		PinResult output = new PinResult();

		ResponseAPDU responseApdu;
		int retriesLeft = -1;

		responseApdu = verifyPIN(retriesLeft, purpose, pin);

		if (0x9000 != responseApdu.getSW()) {
			output.setSuccess(false);
			if (0x6983 == responseApdu.getSW()) {
				output.setBlocked(true);
			}
			if (0x63 != responseApdu.getSW1()) {
			}
			retriesLeft = responseApdu.getSW2() & 0xf;
			output.setRetriesLeft(retriesLeft);
		} else
			output.setSuccess(true);
		return output;
	}

	private ResponseAPDU verifyPIN(final int retriesLeft,
			final PINPurpose purpose, char[] pin) throws CardException {

		final byte[] verifyData = new byte[] { (byte) (0x20 | pin.length),
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, };
		for (int idx = 0; idx < pin.length; idx += 2) {
			final char digit1 = pin[idx];
			final char digit2;
			if (idx + 1 < pin.length) {
				digit2 = pin[idx + 1];
			} else {
				digit2 = '0' + 0xf;
			}
			final byte value = (byte) (byte) ((digit1 - '0' << 4) + (digit2 - '0'));
			verifyData[idx / 2 + 1] = value;
		}
		Arrays.fill(pin, (char) 0); // minimize exposure

		try {

			return this.transmitCommand(BeIDCommandAPDU.VERIFY_PIN, verifyData);
		} finally {
			Arrays.fill(verifyData, (byte) 0); // minimize exposure
		}
	}

	// ----------------------------------------------------------------------------------------------------------------------------------

	private CCID getCCID() {
		if (this.ccid == null) {
			this.ccid = new CCID(this.card);
		}
		return this.ccid;
	}

	/**
	 * Return the CardTerminal that held this BeIdCard when it was detected Will
	 * return null if the physical Card that we represent was removed.
	 * 
	 * @return the cardTerminal this BeIDCard was in when detected, or null
	 */
	public CardTerminal getCardTerminal() {
		return cardTerminal;
	}

	/**
	 * 
	 * @param cardTerminal
	 */
	public void setCardTerminal(CardTerminal cardTerminal) {
		this.cardTerminal = cardTerminal;
	}

	/*
	 * BeIDCommandAPDU encapsulates values sent in CommandAPDU's, to make these
	 * more readable in BeIDCard.
	 */
	private enum BeIDCommandAPDU {
		SELECT_APPLET_0(0x00, 0xA4, 0x04, 0x0C), // TODO these are the same?

		SELECT_APPLET_1(0x00, 0xA4, 0x04, 0x0C), // TODO see above

		SELECT_FILE(0x00, 0xA4, 0x08, 0x0C),

		READ_BINARY(0x00, 0xB0),

		VERIFY_PIN(0x00, 0x20, 0x00, 0x01),

		CHANGE_PIN(0x00, 0x24, 0x00, 0x01), // 0x0024=change
		// reference
		// change
		SELECT_ALGORITHM_AND_PRIVATE_KEY(0x00, 0x22, 0x41, 0xB6), // ISO 7816-8
		// SET
		// COMMAND
		// (select
		// algorithm and
		// key for
		// signature)

		COMPUTE_DIGITAL_SIGNATURE(0x00, 0x2A, 0x9E, 0x9A), // ISO 7816-8 COMPUTE
		// DIGITAL SIGNATURE
		// COMMAND
		RESET_PIN(0x00, 0x2C, 0x00, 0x01),

		GET_CHALLENGE(0x00, 0x84, 0x00, 0x00);

		private final int cla;
		private final int ins;
		private final int p1;
		private final int p2;

		private BeIDCommandAPDU(final int cla, final int ins, final int p1,
				final int p2) {
			this.cla = cla;
			this.ins = ins;
			this.p1 = p1;
			this.p2 = p2;
		}

		private BeIDCommandAPDU(final int cla, final int ins) {
			this.cla = cla;
			this.ins = ins;
			this.p1 = -1;
			this.p2 = -1;
		}

		public int getCla() {
			return this.cla;
		}

		public int getIns() {
			return this.ins;
		}

		public int getP1() {
			return this.p1;
		}

		public int getP2() {
			return this.p2;
		}
	}
}
