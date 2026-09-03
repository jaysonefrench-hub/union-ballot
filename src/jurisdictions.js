/**
 * jurisdictions.js — US state/territory codes shared by the election form,
 * the local-creation form, and the migration that names the default local.
 * Jurisdiction drives jurisdiction-specific legal gates (e.g. the Florida
 * PERC contract-ratification stop), so the list must stay consistent
 * everywhere a jurisdiction is chosen or displayed.
 */
'use strict';

const US_JURISDICTIONS = [
  ['AL', 'Alabama'], ['AK', 'Alaska'], ['AZ', 'Arizona'], ['AR', 'Arkansas'], ['CA', 'California'],
  ['CO', 'Colorado'], ['CT', 'Connecticut'], ['DE', 'Delaware'], ['DC', 'District of Columbia'],
  ['FL', 'Florida'], ['GA', 'Georgia'], ['HI', 'Hawaii'], ['ID', 'Idaho'], ['IL', 'Illinois'],
  ['IN', 'Indiana'], ['IA', 'Iowa'], ['KS', 'Kansas'], ['KY', 'Kentucky'], ['LA', 'Louisiana'],
  ['ME', 'Maine'], ['MD', 'Maryland'], ['MA', 'Massachusetts'], ['MI', 'Michigan'], ['MN', 'Minnesota'],
  ['MS', 'Mississippi'], ['MO', 'Missouri'], ['MT', 'Montana'], ['NE', 'Nebraska'], ['NV', 'Nevada'],
  ['NH', 'New Hampshire'], ['NJ', 'New Jersey'], ['NM', 'New Mexico'], ['NY', 'New York'],
  ['NC', 'North Carolina'], ['ND', 'North Dakota'], ['OH', 'Ohio'], ['OK', 'Oklahoma'], ['OR', 'Oregon'],
  ['PA', 'Pennsylvania'], ['RI', 'Rhode Island'], ['SC', 'South Carolina'], ['SD', 'South Dakota'],
  ['TN', 'Tennessee'], ['TX', 'Texas'], ['UT', 'Utah'], ['VT', 'Vermont'], ['VA', 'Virginia'],
  ['WA', 'Washington'], ['WV', 'West Virginia'], ['WI', 'Wisconsin'], ['WY', 'Wyoming'],
  ['XX', 'Other / outside the United States'],
];

const JURISDICTION_CODES = new Set(US_JURISDICTIONS.map(([code]) => code));

/** Full display name for a two-letter code, or the code itself if unknown. */
function jurisdictionName(code) {
  const hit = US_JURISDICTIONS.find(([c]) => c === code);
  return hit ? hit[1] : code;
}

module.exports = { US_JURISDICTIONS, JURISDICTION_CODES, jurisdictionName };
