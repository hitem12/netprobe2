//
// Created by tomaszp on 27.07.2026.
//
#include <gtest/gtest.h>
#include "Parsers.h"
#include <gmock/gmock.h>

using ::testing::ElementsAre;

using namespace parsers;
class WrongMacTest : public ::testing::TestWithParam<const char*> {};
TEST(MAC_SERIALIZE, base)
{
    auto out = serialize_mac("2e:7c:6c:19:7a:ae");
    ASSERT_TRUE(out.has_value());
    EXPECT_THAT(out.value(), ElementsAre(0x2e, 0x7c, 0x6c, 0x19, 0x7a, 0xae));
}

const char* wrong_mac_array[] = {
    "he:llo",
    "world",
    "2e7c:6c:19:7a:ae",
    "2e:7c:6c:19:7a:a",
    "2e:7c::19:7a:ae",
    ":::::",
    "Ze:7c:6c:19:7a:ae",
    "2e:7c:6c:19:7a",
    "2e:7c:6c:19:7a:",
    "2e:7c:6c:19:7a:ae:ff",
};

TEST_P(WrongMacTest, negative)
{
    const char* input = GetParam();
    auto out = serialize_mac(input);
    ASSERT_FALSE(out.has_value());
}

INSTANTIATE_TEST_SUITE_P(
    ValidStrings,
    WrongMacTest,
    ::testing::ValuesIn(wrong_mac_array)
);