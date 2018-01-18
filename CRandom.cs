         
         var key = RandomNum(6).ToBytes(Encoding.UTF8);
         var counter = RandomNum(6).ToBytes(Encoding.UTF8);
         var otp6 = HOTP(key, counter, 6);
         var otp8 = HOTP(key, counter, 8);
         var otp9 = TOTP(key, 10, 9);
        
        /// <summary>
        /// 生成指定长度随机数
        /// </summary>
        /// <param name="lenght"></param>
        /// <returns></returns>
        public static string RandomNum(int lenght=8)
        {
            RandomNumberGenerator random = new RNGCryptoServiceProvider();
            var randomBytes = new byte[lenght/2];
            random.GetBytes(randomBytes);
            return BitConverter.ToString(randomBytes).Replace("-","");

        }

        /// <summary>
        /// 生成TOTP,随机数
        /// </summary>
        /// <param name="key"></param>
        /// <param name="step"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string TOTP(byte[] key, int step = 60, int length = 6)
        {
            var unixTime = (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            var counter = ((int)unixTime) / step;
            var counterByte = BitConverter.GetBytes(counter);
            return HOTP(key, counterByte, length);
        }

        /// <summary>
        /// 生成HOTP,随机数
        /// </summary>
        /// <param name="key"></param>
        /// <param name="counter"></param>
        /// <param name="lenght"></param>
        /// <returns></returns>
        public static string HOTP(byte[] key, byte[] counter, int lenght = 6)
        {
            var hmac = counter.ToHMACSHA1(key);
            var offset = hmac[hmac.Length - 1] & 0xF;
            var b1 = (hmac[offset] & 0x7F) << 24;
            var b2 = (hmac[offset + 1] & 0xFF) << 16;
            var b3 = (hmac[offset + 2] & 0xFF) << 8;
            var b4 = (hmac[offset + 3] & 0xFF);

            var code = b1 | b2 | b3 | b4;

            var value = code % (int)Math.Pow(10, lenght);
            return value.ToString().PadLeft(lenght, '0');
        }
