package zeromt;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Costs {

    public static int calculateAdd(int operations) {
        return operations * 3;
    }

    public static int calculateSub(int operations) {
        return operations * 3;
    }

    public static int calculateMul(int operations) {
        return operations * 5;
    }

    public static int calculateDiv(int operations) {
        return operations * 5;
    }

    public static int calculateExp(int operations, int exp) {
        if (exp == 0) {
            return operations * 10;
        } else {

            return ceilDouble(operations * (10 + 10 * (1 + customLog(256, exp))));
        }
    }

    public static int calculateEccAdd(int operations, boolean optimized) {
        return optimized ? operations * 150 : operations * 500;
    }

    public static int calculateEccMul(int operations, boolean optimized) {
        return optimized ? operations * 6000 : operations * 40000;
    }

    public static double customLog(double base, double logNumber) {
        return Math.log(logNumber) / Math.log(base);
    }

    public static int ceilDouble(double toCeil) {
        return (int) Math.ceil(toCeil);
    }

    public static int ipaProtOneCosts(boolean optimized) {
        int eccAdd = 1;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);
        int eccMul = 3;
        int eccMulCost = calculateEccMul(eccMul, optimized);
        int total = eccAddCost + eccMulCost;
        System.out.format("Inner Product Argument - Protocol 1 - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int ipaProtTwoCosts(boolean optimized, int n) {
        int mul = 1;
        int mulCost = calculateMul(mul);
        int div = ceilDouble(3 * customLog(2, n));
        int divCost = calculateDiv(div);
        int exp = ceilDouble(2 * customLog(2, n));
        int expCost = calculateExp(exp, 2);
        int eccAdd = 2 + ceilDouble(2 * customLog(2, n)) +
                IntStream.rangeClosed(1, ceilDouble(customLog(2, n))).boxed().map(i -> (int) Math.pow(2, i)).reduce(0, Integer::sum);
        int eccAddCost = calculateEccAdd(eccAdd, optimized);
        int eccMul = 3 + (int) (2 * customLog(2, n)) +
                2 * IntStream.rangeClosed(1, ceilDouble(customLog(2, n))).boxed().map(i -> (int) Math.pow(2, i)).reduce(0, Integer::sum);
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = mulCost + divCost + expCost + eccAddCost + eccMulCost;
        System.out.format("Inner Product Argument - Protocol 2 (Normal) - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("MUL - Op: %,d - Cost: %,d \n", mul, mulCost);
        System.out.format("DIV - Op: %,d - Cost: %,d \n", div, divCost);
        System.out.format("EXP - Op: %,d - Cost: %,d \n", exp, expCost);
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int ipaProtTwoMultiexp(boolean optimized, int n) {
        int mul = 1 + ceilDouble(n * ((customLog(2, n)) - 1));
        int div = ceilDouble(customLog(2, n) + n);
        int exp = ceilDouble(2 * customLog(2, n));

        int eccAdd = 2 * n + ceilDouble(2 * customLog(2, n));
        int eccMul = 3 + 2 * n + ceilDouble(2 * customLog(2, n));
        int total = calculateMul(mul) + calculateDiv(div) + calculateExp(exp, 2) + calculateEccAdd(eccAdd, optimized) + calculateEccMul(eccMul, optimized);
        System.out.format("Inner Product Argument - Protocol 2 (Multiexp) - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("MUL - Op: %,d - Cost: %,d \n", mul, calculateMul(mul));
        System.out.format("DIV - Op: %,d - Cost: %,d \n", div, calculateDiv(div));
        System.out.format("EXP - Op: %,d - Cost: %,d \n", exp, calculateExp(exp, 2));
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, calculateEccAdd(eccAdd, optimized));
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, calculateEccMul(eccMul, optimized));
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int range(boolean optimized, int n, int m) {
        int add = (m * n - 1) /* [<1^mn,y^mn>] */ +
                (m * n - 1) /* [<1^mn,2^mn>] */ +
                (m - 1) /* [sumZ] */;
        int addCost = calculateAdd(add);

        int mul = 1 /* [ * <1^mn, y^mn>] */ +
                1 /* [ * <1^mn, 2^mn>] */ +
                1 /* [ * (t^ - delta)] */ +
                1 /* [ * x] */ +
                1 /* [ * x^2] */;
        int mulCost = calculateMul(mul);

        int sub = 1 /* [ - z^2] */ +
                1 /* [ - sumZ] */ +
                1 /* [ - delta] */ +
                1 /* [ - sab] */;
        int subCost = calculateSub(sub);

        int expY = m * n /* [y^m*n] */;
        int expYCost = IntStream.rangeClosed(0, expY - 1).boxed().map(i -> calculateExp(1, i)).reduce(0, Integer::sum);

        int expTwo = m * n /* [2^m*n] */;
        int expTwoCost = IntStream.rangeClosed(0, expTwo - 1).boxed().map(i -> calculateExp(1, i)).reduce(0, Integer::sum);

        int expZ = m /* [sumZ = z^2+j] */;
        int expZCost = IntStream.rangeClosed(1, expZ).boxed().map(j -> calculateExp(1, 2 + j)).reduce(0, Integer::sum);

        int exp = 1 /* [z^2] */ +
                1 /* [x^2] */;
        int expCost = calculateExp(exp, 2);

        int eccAdd = 1 /* [ + stau*h] */ +
                1 /* [ + (c * x)*T1] */ +
                1 /* [ + (c * x^2)*T2] */;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);

        int eccMul = 1 /* [ * g] */ +
                1 /* [ * h] */ +
                1 /* [ * T1] */ +
                1 /* [ * T2] */;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = addCost + mulCost + subCost + (expYCost + expTwoCost + expZCost + expCost) + eccAddCost + eccMulCost;

        System.out.format("Aggregated Range Proof - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ADD - Op: %,d - Cost: %,d \n", add, addCost);
        System.out.format("MUL - Op: %,d - Cost: %,d \n", mul, mulCost);
        System.out.format("SUB - Op: %,d - Cost: %,d \n", sub, subCost);
        System.out.format("EXP - Op: %,d - Cost: %,d \n", expY + expTwo + expZ + exp, expYCost + expTwoCost + expZCost + expCost);
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int rangeIpaArguments(boolean optimized, int n, int m) {
        int add = (m - 1) /* [sumZ] */;
        int addCost = calculateAdd(add);

        int div = (m * n) /* [y^-mn] */;
        int divCost = calculateDiv(div);

        int expY = (m * n) /* [y^m*n] */;
        int expYCost = IntStream.rangeClosed(0, expY - 1).boxed().map(i -> calculateExp(1, i)).reduce(0, Integer::sum);

        int expYTwo = (m * n) /* [y^m*n] */;
        int expYTwoCost = IntStream.rangeClosed(0, expYTwo - 1).boxed().map(i -> calculateExp(1, i)).reduce(0, Integer::sum);

        int expZ = m /* [sumZ = z^1+j] */;
        int expZCost = IntStream.rangeClosed(1, expZ).boxed().map(j -> calculateExp(1, 1 + j)).reduce(0, Integer::sum);

        int expTwo = n /* [2^n] */;
        int expTwoCost = IntStream.rangeClosed(0, expTwo - 1).boxed().map(i -> calculateExp(1, i)).reduce(0, Integer::sum);

        int eccAdd = 1 /* [ + x*S] */ +
                (m * n - 1) /* [<1^mn,g>] */ +
                1 /* [ - z * <1^mn,g>] */ +
                (m * n - 1) /* [<y^mn,h'>] */ +
                1 /* [ + z * <y^mn,h'>] */ +
                (n - 1) /* [<2^n, h'>] */ +
                1 /* [ + sumZ * <2^n, h'>] */ +
                1 /* [ - mu * h] */;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);


        int eccMul = m * n /* [h o y^-1] */ +
                1 /* [ * S] */ +
                1 /* [ * <1^mn,g>] */ +
                m * n /* [<y^mn,h'>] */ +
                1 /* [ * <y^mn,h'>] */ +
                n /* [<2^n, h'>] */ +
                1 /* [ * <2^n, h'>] */ +
                1 /* [mu * h] */ +
                // Negazioni
                1 /* [ - z ] */ +
                1 /* [ - mu ] */;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = addCost + divCost + (expYCost + expYTwoCost + expTwoCost + expZCost) + eccAddCost + eccMulCost;
        System.out.format("Range-IPA Arguments - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ADD - Op: %,d - Cost: %,d \n", add, addCost);
        System.out.format("DIV - Op: %,d - Cost: %,d \n", div, divCost);
        System.out.format("EXP - Op: %,d - Cost: %,d \n", expY + expYTwo + expTwo + expZ, expYCost + expYTwoCost + expTwoCost + expZCost);
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int sigmaSk(boolean optimized, int n, int m) {
        int eccAdd = 1;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);

        int eccMul = 1 + 1;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = eccAddCost + eccMulCost;
        System.out.format("Sigma SK - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int sigmaR(boolean optimized, int n, int m) {
        int eccAdd = 1;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);

        int eccMul = 1 + 1;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = eccAddCost + eccMulCost;
        System.out.format("Sigma R - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int sigmaAB(boolean optimized, int n, int m) {

        int exp = 1 /* [z^2] */ +
                1 /* [z^2] */;
        int expCost = calculateExp(exp, 2);

        int expZ = m - 1 /* [sumZD = z^i+2] */;
        int expZCost = IntStream.rangeClosed(1, expZ).boxed().map(i -> calculateExp(1, i + 2)).reduce(0, Integer::sum);

        int expZTwo = m - 1 /* [sumZCi = z^i+2] */;
        int expZTwoCost = IntStream.rangeClosed(1, expZTwo).boxed().map(i -> calculateExp(1, i + 2)).reduce(0, Integer::sum);

        int eccAdd = 1 /* [ + ssk] */ +
                1 /* [ - sumD] */ +
                1 /* [ + sumZD] */ +
                1 /* [ + c] */ +
                1 /* [ - sumCi] */ +
                1 /* [ + sumZCi] */ +
                (m - 2) /* [sumD] */ +
                (m - 2) /* [sumZD] */ +
                (m - 2) /* [sumCi] */ +
                (m - 2) /* [sumZCi] */;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);

        int eccMul = 1 /* [ * g] */ +
                1 /* [ * (z^2] */ +
                1 /* [ * (Cr] */ +
                (m - 1) /* [z^i+1 * D] */ +
                1 /* [ * (z^2] */ +
                1 /* [ * (Cl] */ +
                (m - 1) /* [z^i+1 * Ci] */ +
                // Negazioni
                1 /* [ - sumD ] */ +
                1 /* [ - sumCi ] */;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = eccAddCost + eccMulCost + (expCost + expZCost + expZTwoCost);
        System.out.format("Sigma AB - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("EXP - Op: %,d - Cost: %,d \n", exp + expZ + expZTwo, expCost + expZCost + expZTwoCost);
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }

    public static int sigmaY(boolean optimized, int n, int m) {

        int eccAdd = (m - 1) /* [ (y - yi))] */ +
                (m - 2) /* [ sumSrYYi] */ +
                (m - 1) /* [ (C - Ci)] */ +
                (m - 2) /* [ * (sumCCi))] */ +
                1 /* [ + c] */;
        int eccAddCost = calculateEccAdd(eccAdd, optimized);

        int eccMul = (m - 1) /* [ * (y - yi))] */ +
                1 /* [ * (sumCCi))] */ +
                // Negazioni
                (m - 1) /* [ - yi ] */ +
                (m - 1) /* [ - Ci ] */;
        int eccMulCost = calculateEccMul(eccMul, optimized);

        int total = eccAddCost + eccMulCost;
        System.out.format("Sigma Y - %s \n", optimized ? "EIP-1108" : "EIP-196");
        System.out.format("ECC ADD - Op: %,d - Cost: %,d \n", eccAdd, eccAddCost);
        System.out.format("ECC MUL - Op: %,d - Cost: %,d \n", eccMul, eccMulCost);
        System.out.format("TOTAL: %,d \n", total);
        System.out.println("--------------------------------------------------------------------------------------------");
        return total;
    }


    public static void main(String[] args) {
        int n = 64;
        int m = 4;
        boolean opt = true;
        System.out.format("n: %,d - m: %,d \n", n, m);
        System.out.println("############################################################################################");
        System.out.format("TOTAL EIP 1108 Normal: %,d \n", ipaProtOneCosts(opt) +
                ipaProtTwoCosts(opt, n * m) +
                range(opt, n, m) +
                rangeIpaArguments(opt, n, m) +
                sigmaSk(opt, n, m) +
                sigmaR(opt, n, m) +
                sigmaAB(opt, n, m) +
                sigmaY(opt, n, m));
        System.out.println("############################################################################################");
        System.out.format("TOTAL EIP 1108 Multiexp: %,d \n", ipaProtOneCosts(opt) +
                ipaProtTwoMultiexp(opt, n * m) +
                range(opt, n, m) +
                rangeIpaArguments(opt, n, m) +
                sigmaSk(opt, n, m) +
                sigmaR(opt, n, m) +
                sigmaAB(opt, n, m) +
                sigmaY(opt, n, m));
        System.out.println("############################################################################################");
        opt = false;
        System.out.format("TOTAL EIP 196 Normal: %,d \n", ipaProtOneCosts(opt) +
                ipaProtTwoCosts(opt, n * m) +
                range(opt, n, m) +
                rangeIpaArguments(opt, n, m) +
                sigmaSk(opt, n, m) +
                sigmaR(opt, n, m) +
                sigmaAB(opt, n, m) +
                sigmaY(opt, n, m));
        System.out.println("############################################################################################");
        System.out.format("TOTAL EIP 196 Multiexp: %,d \n", ipaProtOneCosts(opt) +
                ipaProtTwoMultiexp(opt, n * m) +
                range(opt, n, m) +
                rangeIpaArguments(opt, n, m) +
                sigmaSk(opt, n, m) +
                sigmaR(opt, n, m) +
                sigmaAB(opt, n, m) +
                sigmaY(opt, n, m));
        System.out.println("############################################################################################");
    }
}
