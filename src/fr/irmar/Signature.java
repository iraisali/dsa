package fr.irmar;

import utils.Constants;

import java.io.Serializable;
import java.math.BigInteger;

public class Signature implements Serializable {

	private BigInteger r;
	private BigInteger s;

	public BigInteger getR() {
		return r;
	}

	public void setR(BigInteger r) {
		this.r = r;
	}

	public BigInteger getS() {
		return s;
	}

	public void setS(BigInteger s) {
		this.s = s;
	}

	public Signature(){
	}

}
