#include <iostream>
#include <string>
#include <array>
#include <charconv>

//Returns an array of all letters a-z and a space, in that order
consteval std::array<char, 27> getLetters()
{
    std::array<char, 27> ret{};
    for (unsigned char i = 0; i < 26; i++)
        ret.at(i) = ('a' + i);
    ret.at(26) = ' ';
    return ret;
}

constinit auto letters = getLetters();

char rotateForward(char v, size_t rotation, bool includeSpaces)
{
    //Skip punctuation, special exclusion for spaces if they are being included
    if (v == ' ')
    {
        if (!includeSpaces)
            return v;
    }
    else if (!std::isalpha(static_cast<unsigned char>(v)))
    {
        return v;
    }
    //Bring the rotation into the range of letters
    rotation %= (letters.size() - !includeSpaces);
    size_t pos = v - 'a'; //Technically this is implementation defined, but this can be ignored for most sane OSs
    if (v == ' ') //Spaces don't adhere to the letter subtraction trick above
        pos = letters.size() - 1;
    const size_t idx = (pos + rotation) % (letters.size() - !includeSpaces);
    return letters[idx];
}

char rotateBackward(char v, size_t rotation, bool includeSpaces)
{
    //Skip punctuation, special exclusion for spaces if they are being included
    if (v == ' ')
    {
        if (!includeSpaces)
            return v;
    }
    else if (!std::isalpha(static_cast<unsigned char>(v)))
    {
        return v;
    }
    rotation %= (letters.size() - !includeSpaces);
    size_t pos = v - 'a'; //Technically this is implementation defined, but this can be ignored for most sane OSs
    if (v == ' ')
        pos = letters.size() - 1;
    if (pos < rotation)
    {
        pos = (letters.size() - !includeSpaces) - (rotation - pos);
    }
    else
    {
        pos -= rotation;
    }
    return letters[pos];
}

std::string cipher(std::string_view str, size_t rotations, bool forward, bool includeSpaces)
{
    std::string ret(str.size(), ' ');
    for (size_t i = 0; i < str.size(); i++)
    {
        if (forward)
            ret[i] = rotateForward(str[i], rotations + i, includeSpaces);
        else
            ret[i] = rotateBackward(str[i], rotations + i, includeSpaces);
    }
    return ret;
}

std::string rotCipher(std::string_view str, size_t rotations, bool forward, bool includeSpaces)
{
    std::string ret(str.size(), ' ');
    for (size_t i = 0; i < str.size(); i++)
    {
        if (forward)
            ret[i] = rotateForward(str[i], rotations, includeSpaces);
        else
            ret[i] = rotateBackward(str[i], rotations, includeSpaces);
    }
    return ret;
}

//Rand is not portable so neither is the ciphertext produced by this function
std::string randCipher(std::string_view str, size_t key, bool forward, bool includeSpaces)
{
    srand(static_cast<unsigned int>(key));
    std::string ret(str.size(), ' ');
    for (size_t i = 0; i < str.size(); i++)
    {
        if (forward)
            ret[i] = rotateForward(str[i], rand(), includeSpaces);
        else
            ret[i] = rotateBackward(str[i], rand(), includeSpaces);
    }
    return ret;
}

template <class Fn>
concept cipherFunction = requires(Fn f, std::string_view s, size_t k, bool fo, bool sp)
{
    {f(s, k, fo, sp)} -> std::same_as<std::string>;
};

template <cipherFunction Fn>
void examine(Fn fn, std::string_view input, std::string_view name, std::string_view ID, size_t key, bool includeSpaces)
{
    const auto enc = fn(input, key, true, includeSpaces);
    std::cout << name << " examples:\n";
    std::cout << "Input:\n\t" << input << "\n";
    std::cout << "Encrypted form (using key " << key << "):\n" << ID << ".0\t" << enc << "\n";
    std::cout << "Output:\n";
    std::cout << ID << ".1\t" << fn(enc, key, false, includeSpaces) 
                                << "\tCorrect Decryption.\n";
    std::cout << ID << ".2\t" << fn(enc, key - 1, false, includeSpaces) 
                                << "\tIncorrect decryption - Wrong key (" << key - 1 << ").\n";
    std::cout << ID << ".3\t" << static_cast<unsigned char>(219)
                                << fn({ enc.begin() + 1, enc.end() }, key, false, includeSpaces)
                                << "\tIncorrect decryption - Skipped first letter.\n";
    std::cout << "\n";
}

int main()
{
    std::string in;
    size_t key = 13;
    do
    {
        std::cout << "Enter plaintext, if not added key will default to 13.\n";
        std::cout << "To add a custom key, end your plaintext with /XX, where XX is a valid positive number.\n";
        std::cout << "Only lower case text will be translated, upper case text will be converted. Non-space punctuation will be skipped.\n";
        std::getline(std::cin, in);
    } while (in.empty());

    auto search = std::find(in.rbegin(), in.rend(), '/');
    if (search != in.rend())
    {
        const char* inPtr = &*(search.base()); //Note that this implicitly skips the current character, '/'
        auto [ptr, ec] = std::from_chars(inPtr, in.data() + in.size(), key);
        if (ec != std::errc() || ptr != in.data() + in.size())
        {
            std::cout << "Unable to parse key, aborting...\n";
            std::cout << "Press [return] to continue...\n";
            std::cin.ignore();
            return 1;
        }
        //Remove trailing "key" information
        in.erase(search.base() - 1, in.end());
    }

    for (auto &i : in)
    {
        if (std::isalpha(static_cast<unsigned char>(i)))
            i = static_cast<char>(std::tolower(static_cast<unsigned char>(i)));
    }


    examine(rotCipher, in, "Rotary cipher without spaces", "Rn", key, false);
    examine(rotCipher, in, "Rotary cipher with spaces", "Rs", key, true);
    examine(cipher, in, "Rotary cipher with index", "Ix", key, true);
    examine(randCipher, in, "Random cipher", "Ra", key, true);
    std::cout << "Press [return] to continue...\n";
    std::cin.ignore();
    return 0;
}