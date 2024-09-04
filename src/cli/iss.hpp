/*!
 * \file
 *
 * Extraction of the .iss file.
 */
#ifndef INNOEXTRACT_CLI_ISS_HPP
#define INNOEXTRACT_CLI_ISS_HPP

#include <iosfwd>

#include "configure.hpp"

#include "cli/extract.hpp"

namespace setup { struct info; }

namespace iss {

void dump_iss(const setup::info & info, const extract_options & o, const boost::filesystem::path & installer);

} // namespace iss

#endif // INNOEXTRACT_CLI_ISS_HPP
