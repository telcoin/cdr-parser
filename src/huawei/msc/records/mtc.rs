use asn1::*;
use super::common::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Record {
    served_msisdn: u64,
}

named!(pub record<Record>,
    do_parse!(
        rec: value!(Record::default())
    >>  rec: apply!(parse, rec)
    >>  eof!()
    >>  (rec)
    )
);

named_args!(parse (rec: Record) <Record>,
    do_parse!(
        rec: apply!(subrec_1_1, rec)
    >>  rec: apply!(subrec_1_2, rec)
    >>  rec: apply!(subrec_1_3, rec)
    >>  (rec)
    )
);

named_args!(subrec_1_1 (rec: Record) <Record>,
    do_parse!(
        rec: apply!(subrec_2_1, rec)
    >>  rec: apply!(subrec_2_2, rec)
    >>  rec: apply!(subrec_2_3, rec)
    >>  rec: apply!(subrec_2_4, rec)
    >>  rec: apply!(subrec_2_5, rec)
    >>  rec: apply!(subrec_2_6, rec)
    >>  rec: apply!(subrec_2_7, rec)
    >>  rec: apply!(subrec_2_8, rec)
    >>  (rec)
    )
);

named_args!(subrec_1_2 (rec: Record) <Record>,
    do_parse!(
        rec: apply!(subrec_2_9, rec)
    >>  rec: apply!(subrec_2_10, rec)
    >>  rec: apply!(subrec_2_11, rec)
    >>  rec: apply!(subrec_2_12, rec)
    >>  rec: apply!(subrec_2_13, rec)
    >>  rec: apply!(subrec_2_14, rec)
    >>  rec: apply!(subrec_2_15, rec)
    >>  rec: apply!(subrec_2_16, rec)
    >>  (rec)
    )
);

named_args!(subrec_1_3 (rec: Record) <Record>,
    do_parse!(
        rec: apply!(subrec_2_17, rec)
    >>  rec: apply!(subrec_2_18, rec)
    >>  rec: apply!(subrec_2_19, rec)
    >>  rec: apply!(subrec_2_20, rec)
    >>  rec: apply!(subrec_2_21, rec)
    >>  (rec)
    )
);

named_args!(subrec_2_1 (rec: Record) <Record>,
    do_parse!(
        _record_type: tlv!(0x80 => ignore)
    >>  _served_imsi: tlv!(0x81 => ignore)
    >>  _served_imei: opt!(tlv!(0x82 => ignore))
    >>  rec: field!(0x83 => address => rec.served_msisdn)
    >>  _calling_number: opt!(tlv!(0x84 => ignore))
    >>  _connected_number: opt!(tlv!(0x85 => ignore))
    >>  _recording_entity: tlv!(0x86 => ignore)
    >>  _msc_incoming_route: opt!(tlv!(0xA7 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_2 (rec: Record) <Record>,
    do_parse!(
        _msc_outgoing_route: opt!(tlv!(0xA8 => ignore))
    >>  _location: tlv!(0xA9 => ignore)
    >>  _change_of_location: opt!(tlv!(0xAA => ignore))
    >>  _basic_service: tlv!(0xAB => ignore)
    >>  _transparency_indicator: opt!(tlv!(0x8C => ignore))
    >>  _change_of_service: opt!(tlv!(0xAD => ignore))
    >>  _suppl_services_used: opt!(tlv!(0xAE => ignore))
    >>  _aoc_parameters: opt!(tlv!(0xAF => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_3 (rec: Record) <Record>,
    do_parse!(
        _change_of_aoc_parameters: opt!(tlv!(0xB0 => ignore))
    >>  _ms_classmark: tlv!(0x91 => ignore)
    >>  _change_of_ms_classmark: opt!(tlv!(0xB2 => ignore))
    >>  _seizure_time: opt!(tlv!(0x93 => ignore))
    >>  _answer_time: tlv!(0x94 => ignore)
    >>  _release_time: tlv!(0x95 => ignore)
    >>  _call_duration: tlv!(0x96 => ignore)
    >>  _radio_chan_requested: opt!(tlv!(0x98 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_4 (rec: Record) <Record>,
    do_parse!(
        _radio_chan_used: opt!(tlv!(0x99 => ignore))
    >>  _change_of_radio_chan: opt!(tlv!(0xBA => ignore))
    >>  _cause_for_term: tlv!(0x9B => ignore)
    >>  _diagnostics: tlv!(0xBC => ignore)
    >>  _call_reference: tlv!(0x9D => ignore)
    >>  _sequence_number: opt!(tlv!(0x9E => ignore))
    >>  _additional_chg_info: tlv!(0xBF, 0x1F => ignore)
    >>  _record_extensions: opt!(tlv!(0xBF, 0x20 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_5 (rec: Record) <Record>,
    do_parse!(
        _network_call_reference: tlv!(0x9F, 0x21 => ignore)
    >>  _msc_address: tlv!(0x9F, 0x22 => ignore)
    >>  _fnur: opt!(tlv!(0x9F, 0x26 => ignore))
    >>  _aiur_requested: opt!(tlv!(0x9F, 0x27 => ignore))
    >>  _speech_version_supported: opt!(tlv!(0x9F, 0x2A => ignore))
    >>  _speech_version_used: opt!(tlv!(0x9F, 0x2B => ignore))
    >>  _gsm_scf_address: opt!(tlv!(0x9F, 0x2C => ignore))
    >>  _service_key: opt!(tlv!(0x9F, 0x2D => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_6 (rec: Record) <Record>,
    do_parse!(
        _system_type: tlv!(0x9F, 0x2E => ignore)
    >>  _rate_indication: opt!(tlv!(0x9F, 0x2F => ignore))
    >>  _partial_record_type: opt!(tlv!(0x9F, 0x36 => ignore))
    >>  _guaranteed_bit_rate: opt!(tlv!(0x9F, 0x37 => ignore))
    >>  _maximum_bit_rate: opt!(tlv!(0x9F, 0x38 => ignore))
    >>  _initial_call_attempt_flag: opt!(tlv!(0x9F, 0x81, 0x09 => ignore))
    >>  _ussd_call_back_flag: opt!(tlv!(0x9F, 0x81, 0x0A => ignore))
    >>  _modem_type: opt!(tlv!(0x9F, 0x81, 0x0B => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_7 (rec: Record) <Record>,
    do_parse!(
        _classmark_3: opt!(tlv!(0x9F, 0x81, 0x0C => ignore))
    >>  _charged_part: tlv!(0x9F, 0x81, 0x0D => ignore)
    >>  _original_called_number: opt!(tlv!(0x9F, 0x81, 0x0E => ignore))
    >>  _cnap_code: opt!(tlv!(0x9F, 0x81, 0x0F => ignore))
    >>  _cnap_result: opt!(tlv!(0x9F, 0x81, 0x10 => ignore))
    >>  _charge_area_code: opt!(tlv!(0x9F, 0x81, 0x11 => ignore))
    >>  _called_charge_area_code: opt!(tlv!(0x9F, 0x81, 0x12 => ignore))
    >>  _default_call_handling: opt!(tlv!(0x9F, 0x81, 0x16 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_8 (rec: Record) <Record>,
    do_parse!(
        _free_format_data: opt!(tlv!(0x9F, 0x81, 0x17 => ignore))
    >>  _free_format_data_append: opt!(tlv!(0x9F, 0x81, 0x18 => ignore))
    >>  _number_of_dp_encountered: opt!(tlv!(0x9F, 0x81, 0x19 => ignore))
    >>  _level_of_camel_service: opt!(tlv!(0x9F, 0x81, 0x1A => ignore))
    >>  _roaming_number: tlv!(0x9F, 0x81, 0x20 => ignore)
    >>  _msc_incoming_circuit: opt!(tlv!(0x9F, 0x81, 0x26 => ignore))
    >>  _org_rnc_or_bsc_id: tlv!(0x9F, 0x81, 0x27 => ignore)
    >>  _org_msc_id: tlv!(0x9F, 0x81, 0x28 => ignore)
    >>  (rec)
    )
);

named_args!(subrec_2_9 (rec: Record) <Record>,
    do_parse!(
        _call_emlpp_priority: opt!(tlv!(0x9F, 0x81, 0x2A => ignore))
    >>  _called_default_mlpp_priority: opt!(tlv!(0x9F, 0x81, 0x2B => ignore))
    >>  _ea_subscriber_info: opt!(tlv!(0x9F, 0x81, 0x2E => ignore))
    >>  _selected_cic: opt!(tlv!(0x9F, 0x81, 0x2F => ignore))
    >>  _optimal_routing_flag: opt!(tlv!(0x9F, 0x81, 0x31 => ignore))
    >>  _caller_ported_flag: opt!(tlv!(0x9F, 0x81, 0x34 => ignore))
    >>  _global_area_id: tlv!(0x9F, 0x81, 0x3C => ignore)
    >>  _change_of_global_area_id: opt!(tlv!(0xBF, 0x81, 0x3D => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_10 (rec: Record) <Record>,
    do_parse!(
        _subscriber_category: tlv!(0x9F, 0x81, 0x3E => ignore)
    >>  _first_mcc_mnc: tlv!(0x9F, 0x81, 0x40 => ignore)
    >>  _intermediate_mcc_mnc: opt!(tlv!(0x9F, 0x81, 0x41 => ignore))
    >>  _last_mcc_mnc: opt!(tlv!(0x9F, 0x81, 0x42 => ignore))
    >>  _cug_outgoing_access_indicator: opt!(tlv!(0x9F, 0x81, 0x43 => ignore))
    >>  _cug_interlock_code: opt!(tlv!(0x9F, 0x81, 0x44 => ignore))
    >>  _cug_incoming_access_used: opt!(tlv!(0x9F, 0x81, 0x45 => ignore))
    >>  _cug_index: opt!(tlv!(0x9F, 0x81, 0x46 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_11 (rec: Record) <Record>,
    do_parse!(
        _hot_billing_tag: opt!(tlv!(0x9F, 0x81, 0x48 => ignore))
    >>  _redirecting_number: opt!(tlv!(0x9F, 0x81, 0x49 => ignore))
    >>  _redirecting_counter: opt!(tlv!(0x9F, 0x81, 0x4A => ignore))
    >>  _setup_time: opt!(tlv!(0x9F, 0x81, 0x4B => ignore))
    >>  _alerting_time: opt!(tlv!(0x9F, 0x81, 0x4C => ignore))
    >>  _called_number: opt!(tlv!(0x9F, 0x81, 0x4D => ignore))
    >>  _voice_number: opt!(tlv!(0x9F, 0x81, 0x4E => ignore))
    >>  _b_category: opt!(tlv!(0x9F, 0x81, 0x4F => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_12 (rec: Record) <Record>,
    do_parse!(
        _call_type: opt!(tlv!(0x9F, 0x81, 0x50 => ignore))
    >>  _group_call_type: opt!(tlv!(0x9F, 0x81, 0x53 => ignore))
    >>  _group_call_reference: opt!(tlv!(0x9F, 0x81, 0x54 => ignore))
    >>  _uss1_type: opt!(tlv!(0x9F, 0x81, 0x55 => ignore))
    >>  _e_category: opt!(tlv!(0x9F, 0x81, 0x57 => ignore))
    >>  _tariff_code: opt!(tlv!(0x9F, 0x81, 0x59 => ignore))
    >>  _disconnect_party: opt!(tlv!(0x9F, 0x81, 0x5A => ignore))
    >>  _cs_reference: opt!(tlv!(0x9F, 0x81, 0x5C => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_13 (rec: Record) <Record>,
    do_parse!(
        _csa_reference: opt!(tlv!(0x9F, 0x81, 0x5D => ignore))
    >>  _network_operator_id: opt!(tlv!(0x9F, 0x81, 0x5F => ignore))
    >>  _type_of_subscribers: opt!(tlv!(0x9F, 0x81, 0x60 => ignore))
    >>  _audio_data_type: opt!(tlv!(0x9F, 0x81, 0x61 => ignore))
    >>  _user_type: opt!(tlv!(0x9F, 0x81, 0x63 => ignore))
    >>  _record_number: opt!(tlv!(0x9F, 0x81, 0x68 => ignore))
    >>  _party_rel_cause: opt!(tlv!(0xBF, 0x81, 0x6C => ignore))
    >>  _charge_level: opt!(tlv!(0x9F, 0x81, 0x6D => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_14 (rec: Record) <Record>,
    do_parse!(
        _location_num: opt!(tlv!(0x9F, 0x81, 0x6E => ignore))
    >>  _zone_info: opt!(tlv!(0x9F, 0x81, 0x70 => ignore))
    >>  _location_number_nai: opt!(tlv!(0x9F, 0x81, 0x71 => ignore))
    >>  _dtmf_indicator: opt!(tlv!(0x9F, 0x81, 0x72 => ignore))
    >>  _b_ch_number: opt!(tlv!(0x9F, 0x81, 0x73 => ignore))
    >>  _translated_number: opt!(tlv!(0x9F, 0x81, 0x75 => ignore))
    >>  _carp: opt!(tlv!(0x9F, 0x81, 0x76 => ignore))
    >>  _map_bypass_ind: opt!(tlv!(0x9F, 0x81, 0x77 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_15 (rec: Record) <Record>,
    do_parse!(
        _channel_mode: opt!(tlv!(0x9F, 0x81, 0x79 => ignore))
    >>  _channel: opt!(tlv!(0x9F, 0x81, 0x7A => ignore))
    >>  _icid_value: opt!(tlv!(0x9F, 0x81, 0x7B => ignore))
    >>  _special_bill_prefix: opt!(tlv!(0x9F, 0x81, 0x7C => ignore))
    >>  _termioi: opt!(tlv!(0x9F, 0x81, 0x7D => ignore))
    >>  _origioi: opt!(tlv!(0x9F, 0x81, 0x7E => ignore))
    >>  _called_ported_flag: opt!(tlv!(0x9F, 0x81, 0x7F => ignore))
    >>  _loaction_routing_number: opt!(tlv!(0x9F, 0x82, 0x00 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_16 (rec: Record) <Record>,
    do_parse!(
        _routing_category: opt!(tlv!(0x9F, 0x82, 0x01 => ignore))
    >>  _intermediate_charging_ind: opt!(tlv!(0x9F, 0x82, 0x02 => ignore))
    >>  _msc_outgoing_route_number: opt!(tlv!(0x9F, 0x82, 0x05 => ignore))
    >>  _msc_incoming_route_number: opt!(tlv!(0x9F, 0x82, 0x06 => ignore))
    >>  _ro_default_call_handling: opt!(tlv!(0x9F, 0x82, 0x07 => ignore))
    >>  _ro_link_failure_time: opt!(tlv!(0x9F, 0x82, 0x08 => ignore))
    >>  _last_succ_ccr_time: opt!(tlv!(0x9F, 0x82, 0x09 => ignore))
    >>  _drc_call_id: opt!(tlv!(0x9F, 0x82, 0x0A => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_17 (rec: Record) <Record>,
    do_parse!(
        _drc_call_rn: opt!(tlv!(0x9F, 0x82, 0x0B => ignore))
    >>  _npdip_indicator: opt!(tlv!(0x9F, 0x82, 0x0C => ignore))
    >>  _ansi_routing_number: opt!(tlv!(0x9F, 0x82, 0x0D => ignore))
    >>  _irn_source: opt!(tlv!(0x9F, 0x82, 0x0E => ignore))
    >>  _vobb_user_flag: opt!(tlv!(0x9F, 0x82, 0x15 => ignore))
    >>  _invoke_of_lcls: opt!(tlv!(0xBF, 0x82, 0x16 => ignore))
    >>  _office_name: opt!(tlv!(0x9F, 0x82, 0x1D => ignore))
    >>  _scp_connection: opt!(tlv!(0x9F, 0x82, 0x1E => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_18 (rec: Record) <Record>,
    do_parse!(
        _charge_class: opt!(tlv!(0x9F, 0x82, 0x1F => ignore))
    >>  _npa_nxx: opt!(tlv!(0x9F, 0x82, 0x21 => ignore))
    >>  _global_call_reference: opt!(tlv!(0x9F, 0x82, 0x22 => ignore))
    >>  _called_ip_information: opt!(tlv!(0x9F, 0x82, 0x24 => ignore))
    >>  _call_drop_ind: opt!(tlv!(0x9F, 0x82, 0x26 => ignore))
    >>  _cause_location: opt!(tlv!(0x9F, 0x82, 0x27 => ignore))
    >>  _intermediate_rate: opt!(tlv!(0x9F, 0x82, 0x29 => ignore))
    >>  _retrieval_of_held_call: opt!(tlv!(0x9F, 0x82, 0x2A => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_19 (rec: Record) <Record>,
    do_parse!(
        _presentation_and_screening_indicator: opt!(tlv!(0x9F, 0x82, 0x2B => ignore))
    >>  _called_num_category: opt!(tlv!(0x9F, 0x82, 0x2E => ignore))
    >>  _group_id: opt!(tlv!(0x9F, 0x82, 0x2F => ignore))
    >>  _vpn_call_property: opt!(tlv!(0x9F, 0x82, 0x30 => ignore))
    >>  _subgroup_id: opt!(tlv!(0x9F, 0x82, 0x31 => ignore))
    >>  _access_network_information: opt!(tlv!(0x9F, 0x82, 0x32 => ignore))
    >>  _ringing_duration: opt!(tlv!(0x9F, 0x82, 0x33 => ignore))
    >>  _call_property: opt!(tlv!(0x9F, 0x82, 0x34 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_20 (rec: Record) <Record>,
    do_parse!(
        _sdp_media_identifier: opt!(tlv!(0x9F, 0x82, 0x35 => ignore))
    >>  _served_party_ip_address: opt!(tlv!(0xBF, 0x82, 0x36 => ignore))
    >>  _number_portability_status: opt!(tlv!(0x9F, 0x82, 0x37 => ignore))
    >>  _anchor_flag: opt!(tlv!(0x9F, 0x82, 0x38 => ignore))
    >>  _ims_service_code: opt!(tlv!(0x9F, 0x82, 0x39 => ignore))
    >>  _additional_routing_category: opt!(tlv!(0x9F, 0x82, 0x3D => ignore))
    >>  _additional_caller_num: opt!(tlv!(0x9F, 0x82, 0x40 => ignore))
    >>  _ics_user_flag: opt!(tlv!(0x9F, 0x82, 0x46 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_21 (rec: Record) <Record>,
    do_parse!(
        _overseas_flag: opt!(tlv!(0x9F, 0x82, 0x48 => ignore))
    >>  _service_attribute: opt!(tlv!(0x9F, 0x82, 0x49 => ignore))
    >>  (rec)
    )
);
