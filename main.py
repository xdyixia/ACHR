import hashlib
import time
import gmpy2
import random

def quickPower(a, b, c):  
    result = 1
    while b > 0:
        if b % 2 == 1:
            result = result * a % c
        a = a * a % c
        b >>= 1
    return result

def treatMSG(msg):  
    newmsg = ''
    for i in msg:
        newmsg += str(ord(i))
    return int(newmsg)

def _get_p(x):
    n = random.randint(10 ** x, 9 * 10 ** x)
    if not gmpy2.is_prime(n):
        n = gmpy2.next_prime(n)
    return n

if __name__ == '__main__':

#ACHR.setup
        t1 = time.perf_counter()

        p1 = _get_p(4)
        q1 = _get_p(4)
        p2 = _get_p(4)
        q2 = _get_p(4)   

        #p1 = _get_p(8)
        #q1 = _get_p(8)
        #p2 = _get_p(8)
        #q2 = _get_p(8)  

        #p1 = _get_p(16)
        #q1 = _get_p(16)
        #p2 = _get_p(16)
        #q2 = _get_p(16)  

        #p1 = _get_p(32)
        #q1 = _get_p(32)
        #p2 = _get_p(32)
        #q2 = _get_p(32)  

        #p1 = _get_p(64)
        #q1 = _get_p(64)
        #p2 = _get_p(64)
        #q2 = _get_p(64)  

        #p1 = _get_p(128)
        #q1 = _get_p(128)
        #p2 = _get_p(128)
        #q2 = _get_p(128)  

        #print(p1)
        #print(q1)
        #print(p2)
        #print(q2)

        N1 = p1 * q1
        e1 = int(65537)
        #p2 = int(10019)
        #q2 = int(1013)
        N2 = p2 * q2
        e2 = int(65537)

        csr = int(9404889194022541)
        H = 'sha256'
        #print('RSA1参数 N1, p1, q1, e1, d1:', N1, p1, q1, e1, d1)
        #print('RSA2参数 N2, p2, q2, e2, d2:', N2, p2, q2, e2, d2)
        t2 = time.perf_counter()
        t11 = t2 - t1
        print("#ACHR.setup所需时间 ms：", (t2 - t1)*1000)
        pp = str(1) + str(e1) + str(e2) + str(N1) + str(N2) + str(csr)
        print("#ACHR.setup输出长度 字节：", len(pp))
        print('---------------------------------------------------')

#ACHR.uKeygen
        t3 = time.perf_counter()
        fi = (p1 - 1) * (q1 - 1)
        #for i in range(fi):  
        #    if e1 * i % fi == 1:
        #        d1 = i
        #        break
        d1 = gmpy2.invert(e1,fi)
        y = int(13) 
        Y = quickPower(y, e1, N1)
        t4 = time.perf_counter()
        #print('(usk ,uvk) = ((d1,y),(e1,Y)):', (d1, y), (e1, Y))
        #t4 = time.perf_counter()
        t22 = t4 - t3
        print("#ACHR.uKeygen所需时间 ms：", (t4 - t3)*1000)
        uskuvk = str(d1) + str(y) + str(e1) + str(Y)
        print("#ACHR.uKeygen输出长度 字节：", len(uskuvk))
        print('---------------------------------------------------')

#ACHR.aKeygen
        t5 = time.perf_counter()
        fi = (p2 - 1) * (q2 - 1)
        #for i in range(fi):  
        #    if e2 * i % fi == 1:
        #        d2 = i
        #        break
        d2 = gmpy2.invert(e2, fi)
        sk_as = int(17)  
        vk_as = quickPower(sk_as, e2, N2)
        tdff = e2
        TDff = d2
        #print('(ask ,avk) = ((skas,tdff),(vkas,TDff)):', (sk_as, e2), (vk_as, d2))
        t6 = time.perf_counter()
        t33 = t6 - t5
        print("#ACHR.aKeygen所需时间 ms：", (t6 - t5)*1000)
        askavk = str(sk_as) + str(e2) + str(vk_as) + str(d2)
        print("#ACHR.aKeygen输出长度 字节：", len(askavk))
        print('---------------------------------------------------')

#ACHR.obtain
        t7 = time.perf_counter()
        cs = int(23) 
        CM = int(1009123456781234)
        pi = int(17)
        #print('CM, pi :', CM, pi)
        t8 = time.perf_counter()
        t44 = t8 - t7
        print("#ACHR.obtain所需时间 ms：", (t8 - t7)*1000)
        CMpi = str(CM) + str(pi)
        print("#ACHR.obtain输出长度 字节：", len(CMpi))
        print('---------------------------------------------------')

#ACHR.issue
        t9 = time.perf_counter()
        w = int(7)
        W_pre = quickPower(w, e1, N1)
        W_sign = W_pre * Y
        temp_str = str(W_sign) + str(CM)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        hs_str = hh.hexdigest()
        hs = treatMSG(hs_str)
        #hs = 1013
        s_ = quickPower(sk_as, hs, N1) * w % N1
        #print('hs_str  :', hs_str)
        #print('hs  :', hs)
        #print('s_  :', s_)

        t10 = time.perf_counter()
        t55 = t10 - t9
        print("#ACHR.issue所需时间 ms：", (t10 - t9)*1000)
        Clen = str(hs) + str(s_)
        print("#ACHR.issue输出长度 字节：", len(Clen))
        print('---------------------------------------------------')

#ACHR.hash
        t11 = time.perf_counter()
        fi = N1
        #for i in range(fi):  
        #    if vk_as * i % fi == 1:
        #        vk_as_ = i
        #        break
        vk_as_ = gmpy2.invert(vk_as, fi)
        W_pre_ = quickPower(s_, e1, N1) * quickPower(vk_as_, hs, N1) % N1
        W_sign_ = W_pre_ * Y
        #print('W_pre_:' ,W_pre_)
        #print('W_sign_:' , W_sign_)
        temp_str = str(W_sign_) + str(CM)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        check_hs = hh.hexdigest()
        #print('check_hs_  :', check_hs)

        m = _get_p(6)
        delta = s_ * y
        M_str = str(hs_str)+ str(delta) + str(CM) + str(m)
        #print('M_str :', M_str)
        hh = hashlib.sha256()
        hh.update(M_str.encode("utf-8"))
        HM_str = hh.hexdigest()
        HM = treatMSG(HM_str)
        r_in = 7
        r_out = 17
        h_in = HM * quickPower(r_in, e1, N1) % N1

        vk_out = quickPower(TDff, y, N1)
        temp_str = str(h_in) + str(e1)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        temp_H = hh.hexdigest()
        temp_H_int = treatMSG(temp_H)
        h_out = temp_H_int * quickPower(r_out, vk_out, N2)%N2
        #print('h_out , r_out, r_in, h_in :', h_out , r_out, r_in, h_in)
        t12 = time.perf_counter()
        t66 = t12 - t11
        print("#ACHR.hash所需时间 ms：", (t12 - t11)*1000)
        hrlen = str(h_out) + str(r_out) + str(r_in) + str(h_in)
        print("#ACHR.hash输出长度 字节：", len(hrlen))
        print('---------------------------------------------------')

#ACHR.extract
        t13 = time.perf_counter()
        W_pre_ = quickPower(s_, e1, N1) * quickPower(vk_as, hs, N1) % N1
        W_sign_ = W_pre_ * Y

        temp_str = str(W_sign_) + str(CM)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        check_hs = hh.hexdigest()
        #print('check_hs_  :', check_hs)

        fi = N1
        #for i in range(fi):  
        #    if TDff * i % fi == 1:
        #        TTDff = i
        #       break
        TTDff = gmpy2.invert(TDff, fi)
        sk_out = tdff * TDff * quickPower(TTDff, y, N1) % N1
        #print('sk_out :', sk_out)
        t14 = time.perf_counter()
        t77 = t14 - t13
        print("#ACHR.extract所需时间 ms：", (t14 - t13)*1000)
        yskout = str(y) + str(sk_out)
        print("#ACHR.extract输出长度 字节：", len(yskout))
        print('---------------------------------------------------')

#ACHR.adapt
        t15 = time.perf_counter()
        M_ = str(hs_str) + str(delta) + str(CM) + str(m)
        W_pre_ = quickPower(s_, e1, N1) * quickPower(vk_as_, hs, N1) % N1
        W_sign_ = W_pre_ * Y

        temp_str = str(W_sign_) + str(CM)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        check_hs = hh.hexdigest()
        #print('check_hs_  :', check_hs)
        x_in = HM
        #print('M_ :', M_)
        hh = hashlib.sha256()
        hh.update(M_.encode("utf-8"))
        HM_str_ = hh.hexdigest()
        HM_ = treatMSG(HM_str_)
        x_in_ = HM_
        #print('x_in_ :', x_in_)
        z_in = x_in * quickPower(r_in, e1, N1) % N1
        fi = N1
        #for i in range(fi):  
        #    if x_in_ * i % fi == 1:
        #        xx_in_ = i
        #        break
        xx_in_ = gmpy2.invert(x_in_, fi)
        rr_in = quickPower(z_in * x_in_, d1, N1)
        #print('rr_in :', rr_in)
        t16 = time.perf_counter()
        t88 = t16 - t15
        print("#ACHR.adapt所需时间 ms：", (t16 - t15)*1000)
        r_len = str(r_out) + str(r_in) + str(h_in)
        print("#ACHR.adapt输出长度 字节：", len(r_len))
        print('---------------------------------------------------')

#ACHR.check
        t17 = time.perf_counter()
        W_pre_ = quickPower(s_, e1, N1) * quickPower(vk_as, hs, N1) % N1
        W_sign_ = W_pre_ * Y
        h = h_out
        temp_str = str(h_in) + str(e1)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        temp_H = hh.hexdigest()
        temp_H_int = treatMSG(temp_H)
        h_out_ = temp_H_int * quickPower(r_out, vk_out, N2) % N2

        if h_in == (HM * quickPower(r_in, e1, N1))%N1:
            b_in = 1
        else:
            b_in = 0

        if h_out ==  h_out_:
            b_out = 1
        else:
            b_out = 0
        #print('b_in :', b_in)
        #print('b_out :', b_out)
        t18 = time.perf_counter()
        t99 = t18 - t17
        print("#ACHR.check所需时间 ms：", (t18 - t17)*1000)
        blen = str(b_in)
        print("#ACHR.check输出长度 字节：", len(blen))
        print('---------------------------------------------------')

#ACHR.revoke
        t19 = time.perf_counter()
        p1_ = int(3)
        q1_ = int(11)
        N1_ = p1 * q1
        e1_ = int(43)
        fi = (p1 - 1) * (q1 - 1)
        #for i in range(fi):  
        #    if e1_ * i % fi == 1:
        #        d1_ = i
        #        break
        d1_ = gmpy2.invert(e1_, fi)
        #print('RSA参数 N1_, p1_, q1_, e1_, d1_:', N1_, p1_, q1_, e1_, d1_)

        h = h_out
        r_in_ = 11
        h_in_ = HM_ * quickPower(r_in_, e1_, N1_) % N1

        temp_str = str(h_in) + str(e1)
        hh = hashlib.sha256()
        hh.update(temp_str.encode("utf-8"))
        temp_H = hh.hexdigest()
        temp_H_int = treatMSG(temp_H)
        x_out = temp_H_int
        #print('x_out :', x_out)
        z_out = x_out * quickPower(r_out, e1_, N1_)
        #print('z_out :', z_out)

        fi = N1
        #for i in range(fi):  
        #    if x_out * i % fi == 1:
        #        xx_out = i
        #        break
        xx_out = gmpy2.invert(x_out, fi)
        r_out_ = quickPower(z_out * xx_out, sk_out, N1)
        #print('r_out_ :', r_out_)
        #print('r_in_ :', r_in_)
        #print('h_in_ :', h_in_)
        #print('d1_ :', d1_)
        #print('e1_ :', e1_)
        t20 = time.perf_counter()
        t1010 = t20 - t19
        print("#ACHR.revoke所需时间 ms：", (t20 - t19)*1000)
        rskvk = str(r_out_) + str(r_in_) + str(h_in_) + str(d1_) + str(e1_)
        print("#ACHR.revoke输出长度 字节：", len(rskvk))
        print('---------------------------------------------------')
        totle = t11 + t22 + t33 + t44 + t55 + t66 + t77 + t88 + t99 + t1010
        print("总共所需时间 ms：", totle*1000)
