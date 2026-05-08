#include <gtest/gtest.h>
#include <string>

// Example utility function tests
class UtilsTest : public ::testing::Test {
};

TEST_F(UtilsTest, StringConversion) {
    std::string input = "hello";
    std::string expected = "hello";
    EXPECT_EQ(input, expected);
}

TEST_F(UtilsTest, BasicArithmetic) {
    int a = 10;
    int b = 20;
    EXPECT_EQ(a + b, 30);
}

TEST_F(UtilsTest, VectorOperations) {
    std::vector<int> vec = {1, 2, 3, 4, 5};
    EXPECT_EQ(vec.size(), 5);
    EXPECT_EQ(vec[0], 1);
    EXPECT_EQ(vec[4], 5);
}
