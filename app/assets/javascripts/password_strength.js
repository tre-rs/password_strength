(function(){
  var MULTIPLE_NUMBERS_RE = /\d.*?\d.*?\d/;
  var MULTIPLE_SYMBOLS_RE = /[!@#$%^&*?_~].*?[!@#$%^&*?_~]/;
  var UPPERCASE_LOWERCASE_RE = /([a-z].*[A-Z])|([A-Z].*[a-z])/;
  var SYMBOL_RE = /[!@#\$%^&*?_~]/;

  function escapeForRegexp(string) {
    return (string || "").replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");
  }

  function PasswordStrength() {
    this.username = null;
    this.password = null;
    this.score = 0;
    this.status = null;
  }

  PasswordStrength.fn = PasswordStrength.prototype;

  PasswordStrength.fn.test = function() {
    var score;
    this.score = score = 0;

    if (this.containInvalidMatches()) {
      this.status = "invalid";
    } else if (this.usesCommonWord()) {
      this.status = "invalid";
    } else if (this.containInvalidRepetition()) {
      this.status = "invalid";
    } else {
      score += this.scoreFor("password_size");
      score += this.scoreFor("numbers");
      score += this.scoreFor("symbols");
      score += this.scoreFor("uppercase_lowercase");
      score += this.scoreFor("numbers_chars");
      score += this.scoreFor("numbers_symbols");
      score += this.scoreFor("symbols_chars");
      score += this.scoreFor("only_chars");
      score += this.scoreFor("only_numbers");
      score += this.scoreFor("username");
      score += this.scoreFor("sequences");
      score += this.scoreFor("repetitions");

      if (score < 0) {
        score = 0;
      }

      if (score > 100) {
        score = 100;
      }

      if (score < 35) {
        this.status = "weak";
      }

      if (score >= 35 && score < 70) {
        this.status = "good";
      }

      if (score >= 70) {
        this.status = "strong";
      }
    }

    this.score = score;
    return this.score;
  };

  PasswordStrength.fn.scoreFor = function(name) {
    var score = 0;

    switch (name) {
      case "password_size":
        if (this.password.length < 6) {
          score = -100;
        } else {
          score = this.password.length * 4;
        }
        break;

      case "numbers":
        if (this.password.match(MULTIPLE_NUMBERS_RE)) {
          score = 5;
        }
        break;

      case "symbols":
        if (this.password.match(MULTIPLE_SYMBOLS_RE)) {
          score = 5;
        }
        break;

      case "uppercase_lowercase":
        if (this.password.match(UPPERCASE_LOWERCASE_RE)) {
          score = 10;
        }
        break;

      case "numbers_chars":
        if (this.password.match(/[a-z]/i) && this.password.match(/[0-9]/)) {
          score = 15;
        }
        break;

      case "numbers_symbols":
        if (this.password.match(/[0-9]/) && this.password.match(SYMBOL_RE)) {
          score = 15;
        }
        break;

      case "symbols_chars":
        if (this.password.match(/[a-z]/i) && this.password.match(SYMBOL_RE)) {
          score = 15;
        }
        break;

      case "only_chars":
        if (this.password.match(/^[a-z]+$/i)) {
          score = -15;
        }
        break;

      case "only_numbers":
        if (this.password.match(/^\d+$/i)) {
          score = -15;
        }
        break;

      case "username":
        if (this.password == this.username) {
          score = -100;
        } else if (this.password.indexOf(this.username) != -1) {
          score = -15;
        }
        break;

      case "sequences":
        score += -15 * this.sequences(this.password);
        score += -15 * this.sequences(this.reversed(this.password));
        break;

      case "repetitions":
        score += -(this.repetitions(this.password, 2) * 4);
        score += -(this.repetitions(this.password, 3) * 3);
        score += -(this.repetitions(this.password, 4) * 2);
        break;
    };

    return score;
  };

  PasswordStrength.fn.isGood = function() {
    return this.status == "good";
  };

  PasswordStrength.fn.isWeak = function() {
    return this.status == "weak";
  };

  PasswordStrength.fn.isStrong = function() {
    return this.status == "strong";
  };

  PasswordStrength.fn.isInvalid = function() {
    return this.status == "invalid";
  };

  PasswordStrength.fn.isValid = function(level) {
    if(level == "strong") {
      return this.isStrong();
    } else if (level == "good") {
      return this.isStrong() || this.isGood();
    } else {
      return !this.containInvalidMatches() && !this.usesCommonWord();
    }
  };

  PasswordStrength.fn.containInvalidMatches = function() {
    if (!this.exclude) {
      return false;
    }

    if (!this.exclude.test) {
      return false;
    }

    return this.exclude.test(this.password.toString());
  };

  PasswordStrength.fn.containInvalidRepetition = function() {
    var char = this.password[0];

    if (!char) {
      return;
    }

    var regex = new RegExp("^" + escapeForRegexp(char) + "+$", "i");

    return regex.test(this.password);
  };

  PasswordStrength.fn.usesCommonWord = function() {
    return PasswordStrength.commonWords.indexOf(this.password.toLowerCase()) >= 0;
  };

  PasswordStrength.fn.sequences = function(text) {
    var matches = 0;
    var sequenceSize = 0;
    var codes = [];
    var len = text.length;
    var previousCode, currentCode;

    for (var i = 0; i < len; i++) {
      currentCode = text.charCodeAt(i);
      previousCode = codes[codes.length - 1];
      codes.push(currentCode);

      if (previousCode) {
        if (currentCode == previousCode + 1 || previousCode == currentCode) {
          sequenceSize += 1;
        } else {
          sequenceSize = 0;
        }
      }

      if (sequenceSize == 2) {
        matches += 1;
      }
    }

    return matches;
  };

  PasswordStrength.fn.repetitions = function(text, size) {
    var count = 0;
    var matches = {};
    var len = text.length;
    var substring;
    var occurrences;
    var tmpText;

    for (var i = 0; i < len; i++) {
      substring = text.substr(i, size);
      occurrences = 0;
      tmpText = text;

      if (matches[substring] || substring.length < size) {
        continue;
      }

      matches[substring] = true;

      while ((i = tmpText.indexOf(substring)) != -1) {
        occurrences += 1;
        tmpText = tmpText.substr(i + 1);
      };

      if (occurrences > 1) {
        count += 1;
      }
    }

    return count;
  };

  PasswordStrength.fn.reversed = function(text) {
    var newText = "";
    var len = text.length;

    for (var i = len -1; i >= 0; i--) {
      newText += text.charAt(i);
    }

    return newText;
  };

  PasswordStrength.test = function(username, password) {
    var strength = new PasswordStrength();
    strength.username = username;
    strength.password = password;
    strength.test();
    return strength;
  };

  PasswordStrength.commonWords = ["teste", "teste1", "teste123", "teste1234", "87654321", "987654321", "senha", "senha1", "senha123", "senha1234", "s3nh4", "minhasenha", "tre1234", "trers", "eleitoral123", "acesso1", "acesso12", "acesso123", "admin", "admin123", "admin1234", "apollo1", "apollo12", "apollo123", "sentencas1", "segredo", "meusegredo", "segredo1", "segredo123", "qwerty", "qwertyuiop", "123qwe", "1q2w3e4r", "q1w2e3r4", "q1w2e3", "1q2w3e", "1q2w3e4r5t", "!qaz1qaz", "!qaz2wsx", "!qazxsw2", "!qazzaq1", "#edc4rfv", "qazwsxedc", "000000", "010203", "1111", "11111", "111111", "11111111", "112233", "1212", "121212", "123123", "12", "123", "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890", "09", "098", "0987", "09876", "098765", "0987654", "09876543", "098765432", "0987654321", "123qweasd", "12qw!@qw", "1313", "131313", "1qaz!qaz", "1qaz2wsx", "1qaz@wsx", "1qazxsw@", "1qazzaq!", "2000", "2112", "2222", "232323", "2wsx@wsx", "3333", "3edc#edc", "4128", "4321", "4444", "5150", "5555", "55555", "555555", "654321", "6666", "666666", "6969", "696969", "7777", "777777", "7777777", "8675309", "987654", "987654321", "@wsx2wsx", "aaaa", "aaaaaa", "abc123", "abc123abc", "abcabc123", "abcd1234", "abcdef", "asdfgh", "asdfgfdsa", "asdfdsa", "pass", "pass1234", "passion1", "passw0rd", "passw0rd1", "password", "password01", "password1", "password1!", "password11", "password12", "password123", "password13", "password2", "password21", "password3", "password4", "password5", "password7", "password9", "xxxx", "xxxxx", "xxxxxx", "xxxxxxxx", "zaq!1qaz", "zaq!2wsx", "zaq!xsw2", "zaq1!qaz", "zaq1@wsx", "zaq1zaq!", "zxcvbn", "zxcvbnm", "zzzzzz"];

  if (typeof(module) === "object" && module.exports) {
    module.exports = PasswordStrength;
  } else if (typeof define === "function" && define.amd) {
    define("password_strength", [], function() {
      return PasswordStrength;
    });
  } else if (typeof(window) === "object") {
    window.PasswordStrength = PasswordStrength;
  }
})();
