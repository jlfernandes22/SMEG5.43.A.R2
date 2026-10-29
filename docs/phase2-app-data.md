# Phase 2 application segments and databases

> **Historical phase record.** Unresolved checksum suffixes, segment addresses, and behavior describe the evidence available in this phase. For the current consolidated findings and limits, start with [REVERSE_ENGINEERING.md](REVERSE_ENGINEERING.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

Observed directly in the supplied SMEG5.43.A.R2 package. Reproduce with `python3 scripts/inspect_app_data.py`. Package, first application extraction, and databases remain unmodified; second segments are separate output files.

## Integrity and application boundaries

The upstream `verify_package.audit()` reports no package checksum-chain problems. The `verify_package.py --json` command independently reports no problems or warnings. Container sidecar CRC32 fields match all three complete `f_BigQuick.bin` files. Both zlib streams in every container decode to end-of-stream, validating their built-in Adler32 checks. Main images match the previous payload manifest and extracted `app.bin` byte-for-byte. CRCs establish consistency, not authenticity.

Each container has a 2 KiB table of 64 entries (32 bytes each), two used entries, and 62 entries filled with `0xdeadbeef`. Entry 0 describes the main segment at marker offset `0x800` / zlib offset `0x801`. Entry 1 contains a block offset: `(word0 + 1) * 2048` identifies a second `0x08` marker and another complete zlib stream. For both entries, word1 matches the inflated size and word5 matches one marker byte plus compressed stream plus a two-byte suffix. Other header words are retained without interpreting them.

| Variant | Main inflated bytes | Main CRC32 | Complete-container CRC32 | Second zlib offset | Second inflated bytes | Second CRC32 |
|---|---:|---|---|---|---:|---|
| AUDIO_BT | 32434440 | `1d133632` | `39fdab35` | `0x96b801` | 15231744 | `79ba6c94` |
| AUDIO_BT_256 | 32434440 | `daaa46a9` | `c380bfd9` | `0x96b801` | 15231744 | `174f2522` |
| NAV | 39863376 | `8abce58a` | `7763afe0` | `0xbe7801` | 15254496 | `b6fd002a` |

The approximately 3.9 MB previously reported as unused zlib data contains the second stream, a two-byte suffix after each stream, and alignment padding. Between the first suffix and second marker every padding byte is `0xEE`. Exactly two bytes remain after the second zlib stream. The suffix interpretation is not established. Second images were extracted to `artifacts/phase2/applications/<variant>/app_segment2.bin`; their runtime purpose and load addresses require separate analysis. Full offsets, hashes, header words, and suffix bytes are in `artifacts/phase2/app-data-evidence.json`.

## Actual SQLite inventory

There are 87 extracted SQLite files: 29 names in each of NAV, AUDIO_BT and AUDIO_BT_256. The variants contain exactly the same 29 content hashes; no database is gzip wrapped. Each opens read-only and its table schema was inventoried without errors. These are update-package defaults, not a readback of the installed vehicle databases.

`config_options.sqlite` exists and contains `sw_option(name VARCHAR, value INTEGER)`, with zero rows. `config.sqlite` contains the same two-column format in `config_system`, also with zero rows. No populated feature names can be recovered from these default tables.

`up_config.sqlite` exists and has 271 rows in `UP_Keys`: `Section`, `Name`, `Type`, `Idx`, `IntValue`, `FloatValue`, `StringValue`, `BlobValue`, `reset_factory_enabled`, `modified`; primary key `(Section, Name, Idx)`. It has no generic name/value schema. A mutation script must respect this schema and the key type.

Observed NAV default keys include `internet/Smartapps` (`Type=2`, `Idx=0`, `IntValue=0`) and `navigation/Diag_SpeedLimit_Activation` and `navigation/Diag_SpeedTrap_Activation` (both `IntValue=1`). These names and defaults establish stored settings only; they do not prove feature behavior or hardware capability. No CarPlay or Android key matched the targeted name search. `Speed_Limiter_Stop` is a speed-limiter setting; its name does not establish Stop/Start engine control.

| SQLite file | Tables |
|---|---|
| KeyboardHistory.sqlite | contact_email, contact_firstname, contact_street, contact_surname, contact_town, sqlite_sequence |
| Pictures.sqlite | Entries, Managers, sqlite_sequence |
| RadioLogo.sqlite | PI_Logo_List |
| Trip.sqlite | Trip_data |
| agenda.sqlite | ACP, AgendaElementIdentifier, BTPhoneBook, Email, InternalPhoneBook, NavigationAddress, NavigationCoordinate, PhoneNumber, PostalAddress, ProfilePicture |
| browser.sqlite | bookmarks, cookies, errors, history, preferences, sqlite_sequence, usernamePassword |
| cheatcodes.sqlite | cheatcodes |
| config.sqlite | config_system |
| config_options.sqlite | sw_option |
| connectivity.sqlite | devices, dun, errors, pincodes, sqlite_sequence, usb3g, wifi, wifi_list |
| db_alerts.sqlite | PanelReference, Vhl_list, alerts, city_park_cam, city_park_no_cam, jda_alerts, labels, silhouette, vhl_param_order |
| db_manager.sqlite | databases |
| desktopServices.sqlite | current_carrousel, current_menu, execute |
| diag_zi.sqlite | ZI |
| diagnosis.sqlite | activities_state, extra_data, failures_current_and_ack_order, failures_historic, versions |
| media_catalog.sqlite | AudioFile, AudioFileTag, AudioPlaylist, AudioPlaylistItem, Device, ImageFile, VideoFile |
| media_cdc_catalog.sqlite | AudioFile, CDC_General |
| media_jkb_catalog.sqlite | AudioFile, AudioFileTag, InternalFileSystem |
| nav_dest.sqlite | POI_filter_name, POI_filter_name_historic, POI_search_result, archive_historic, city, city_historic, country, country_historic, crossroad, keyboard_city_historic, keyboard_road_historic, last_destination, road, road_historic, waypoint |
| nav_poi.sqlite | Brand, BrandByIHMSubCat, IHMCategory, IHMCategoryType, IHMSubCatByCat, IHMSubCategory, ModuleVersion, ZARAssociation, sqlite_stat1 |
| navigation.sqlite | LastDestinations, WayPoints |
| tuner.sqlite | AM_Preset_info, AM_Stations_list, Current_mem_index, DAB_Preset_info, DAB_Services_list, Data_service_journaline_info_list_msg, Data_service_journaline_info_menu_links, Data_service_journaline_info_menu_obj, Data_service_journaline_info_plain_text_formats, Data_service_journaline_info_text_msg, Data_service_journaline_info_title_only, Data_service_journaline_list, Data_service_list_programme, FM_Preset_info, FM_Stations_list, TMC_Stations_list |
| up_common.sqlite | UP_Keys |
| up_config.sqlite | UP_Keys |
| up_user.sqlite | UP_Keys |
| up_user_hmi.sqlite | UP_Keys |
| upgrade.sqlite | DRM |
| version_history.sqlite | version_history |
| versions.sqlite | versions |

The evidence JSON contains every table SQL definition and column name/type, plus row counts for the configuration databases and the exact feature-name search results. No settings were changed.
