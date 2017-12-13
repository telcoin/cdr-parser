use asn1::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Record;

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
    >>  (rec)
    )
);

named_args!(subrec_2_1 (rec: Record) <Record>,
    do_parse!(
        _record_type: tlv!(0x80 => ignore)
    >>  _calling_number: opt!(tlv!(0x81 => ignore))
    >>  _called_number: tlv!(0x82 => ignore)
    >>  _recording_entity: tlv!(0x83 => ignore)
    >>  _msc_incoming_route: opt!(tlv!(0xA4 => ignore))
    >>  _msc_outgoing_route: opt!(tlv!(0xA5 => ignore))
    >>  _seizure_time: opt!(tlv!(0x86 => ignore))
    >>  _answer_time: tlv!(0x87 => ignore)
    >>  (rec)
    )
);

named_args!(subrec_2_2 (rec: Record) <Record>,
    do_parse!(
        _release_time: tlv!(0x88 => ignore)
    >>  _call_duration: tlv!(0x89 => ignore)
    >>  _cause_for_term: tlv!(0x8B => ignore)
    >>  _diagnostics: tlv!(0xAC => ignore)
    >>  _call_reference: tlv!(0x8D => ignore)
    >>  _sequence_number: opt!(tlv!(0x8E => ignore))
    >>  _record_extensions: opt!(tlv!(0xAF => ignore))
    >>  _partial_record_type: opt!(tlv!(0x96 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_3 (rec: Record) <Record>,
    do_parse!(
        _basic_service: tlv!(0xBF, 0x81, 0x02 => ignore)
    >>  _additional_chg_info: tlv!(0xBF, 0x81, 0x05 => ignore)
    >>  _ussd_call_back_flag: opt!(tlv!(0x9F, 0x81, 0x0A => ignore))
    >>  _charged_party: opt!(tlv!(0x9F, 0x81, 0x0D => ignore))
    >>  _original_called_number: opt!(tlv!(0x9F, 0x81, 0x0E => ignore))
    >>  _charge_area_code: opt!(tlv!(0x9F, 0x81, 0x11 => ignore))
    >>  _rate_indication: opt!(tlv!(0x9F, 0x81, 0x1F => ignore))
    >>  _roaming_number: opt!(tlv!(0x9F, 0x81, 0x20 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_4 (rec: Record) <Record>,
    do_parse!(
        _msc_outgoing_circuit: opt!(tlv!(0x9F, 0x81, 0x26 => ignore))
    >>  _org_msc_id: opt!(tlv!(0x9F, 0x81, 0x28 => ignore))
    >>  _call_emlpp_priority: opt!(tlv!(0x9F, 0x81, 0x2A => ignore))
    >>  _ea_subscriber_info: opt!(tlv!(0x9F, 0x81, 0x2E => ignore))
    >>  _selected_cic: opt!(tlv!(0x9F, 0x81, 0x2F => ignore))
    >>  _caller_ported_flag: opt!(tlv!(0x9F, 0x81, 0x34 => ignore))
    >>  _subscriber_category: opt!(tlv!(0x9F, 0x81, 0x3E => ignore))
    >>  _cug_outgoing_access_indicator: opt!(tlv!(0x9F, 0x81, 0x43 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_5 (rec: Record) <Record>,
    do_parse!(
        _cug_interlock_code: opt!(tlv!(0x9F, 0x81, 0x44 => ignore))
    >>  _cug_incoming_access_used: opt!(tlv!(0x9F, 0x81, 0x45 => ignore))
    >>  _msc_incoming_route_attribute: opt!(tlv!(0x9F, 0x81, 0x46 => ignore))
    >>  _msc_outgoing_route_attribute: opt!(tlv!(0x9F, 0x81, 0x47 => ignore))
    >>  _network_call_reference: tlv!(0x9F, 0x81, 0x48 => ignore)
    >>  _setup_time: opt!(tlv!(0x9F, 0x81, 0x49 => ignore))
    >>  _alerting_time: opt!(tlv!(0x9F, 0x81, 0x4A => ignore))
    >>  _voice_indicator: opt!(tlv!(0x9F, 0x81, 0x4B => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_6 (rec: Record) <Record>,
    do_parse!(
        _b_category: opt!(tlv!(0x9F, 0x81, 0x4C => ignore))
    >>  _call_type: opt!(tlv!(0x9F, 0x81, 0x4D => ignore))
    >>  _charge_pulse_num: opt!(tlv!(0x9F, 0x81, 0x4E => ignore))
    >>  _disconnected_party: opt!(tlv!(0x9F, 0x81, 0x5A => ignore))
    >>  _charge_pulse_num_for_itxtxa: opt!(tlv!(0x9F, 0x81, 0x5B => ignore))
    >>  _network_operator_id: opt!(tlv!(0x9F, 0x81, 0x5F => ignore))
    >>  _audio_data_type: opt!(tlv!(0x9F, 0x81, 0x61 => ignore))
    >>  _record_number: opt!(tlv!(0x9F, 0x81, 0x68 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_7 (rec: Record) <Record>,
    do_parse!(
        _party_rel_cause: opt!(tlv!(0xBF, 0x81, 0x6C => ignore))
    >>  _charge_level: opt!(tlv!(0x9F, 0x81, 0x6D => ignore))
    >>  _location_num: opt!(tlv!(0x9F, 0x81, 0x6E => ignore))
    >>  _location_number_nai: opt!(tlv!(0x9F, 0x81, 0x71 => ignore))
    >>  _translated_number: opt!(tlv!(0x9F, 0x81, 0x75 => ignore))
    >>  _location: opt!(tlv!(0xBF, 0x81, 0x77 => ignore))
    >>  _change_of_location: opt!(tlv!(0xBF, 0x81, 0x78 => ignore))
    >>  _first_mcc_mnc: opt!(tlv!(0x9F, 0x81, 0x79 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_8 (rec: Record) <Record>,
    do_parse!(
        _last_mcc_mnc: opt!(tlv!(0x9F, 0x81, 0x7A => ignore))
    >>  _icid_value: opt!(tlv!(0x9F, 0x81, 0x7B => ignore))
    >>  _origioi: opt!(tlv!(0x9F, 0x81, 0x7C => ignore))
    >>  _termioi: opt!(tlv!(0x9F, 0x81, 0x7D => ignore))
    >>  _called_ported_flag: opt!(tlv!(0x9F, 0x81, 0x7F => ignore))
    >>  _location_routing_number: opt!(tlv!(0x9F, 0x82, 0x80 => ignore))
    >>  _intermediate_charging_indicator: opt!(tlv!(0x9F, 0x82, 0x02 => ignore))
    >>  _msc_outgoing_route_number: opt!(tlv!(0x9F, 0x82, 0x05 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_9 (rec: Record) <Record>,
    do_parse!(
        _msc_incoming_route_number: opt!(tlv!(0x9F, 0x82, 0x06 => ignore))
    >>  _drc_call_id: opt!(tlv!(0x9F, 0x82, 0x0A => ignore))
    >>  _drc_call_rn: opt!(tlv!(0x9F, 0x82, 0x0B => ignore))
    >>  _npdip_indicator: opt!(tlv!(0x9F, 0x82, 0x0C => ignore))
    >>  _ansi_routing_number: opt!(tlv!(0x9F, 0x82, 0x0D => ignore))
    >>  _lrn_source: opt!(tlv!(0x9F, 0x82, 0x0E => ignore))
    >>  _wps_call_flag: opt!(tlv!(0x9F, 0x82, 0x0F => ignore))
    >>  _redirecting_number: opt!(tlv!(0x9F, 0x82, 0x10 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_10 (rec: Record) <Record>,
    do_parse!(
        _redirecting_counter: opt!(tlv!(0x9F, 0x82, 0x11 => ignore))
    >>  _office_name: opt!(tlv!(0x9F, 0x82, 0x1D => ignore))
    >>  _scp_connection: opt!(tlv!(0x9F, 0x82, 0x1E => ignore))
    >>  _charge_class: opt!(tlv!(0x9F, 0x82, 0x1F => ignore))
    >>  _npa_nxx: opt!(tlv!(0x9F, 0x82, 0x21 => ignore))
    >>  _global_call_reference: opt!(tlv!(0x9F, 0x82, 0x22 => ignore))
    >>  _caller_ip_information: opt!(tlv!(0xBF, 0x82, 0x23 => ignore))
    >>  _called_ip_information: opt!(tlv!(0xBF, 0x82, 0x24 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_11 (rec: Record) <Record>,
    do_parse!(
        _cause_location: opt!(tlv!(0x9F, 0x82, 0x27 => ignore))
    >>  _presentation_and_screening_indicator: opt!(tlv!(0x9F, 0x82, 0x2B => ignore))
    >>  _calling_nir: opt!(tlv!(0x9F, 0x82, 0x2C => ignore))
    >>  _called_num_category: opt!(tlv!(0x9F, 0x82, 0x2E => ignore))
    >>  _number_portability_status: opt!(tlv!(0x9F, 0x82, 0x37 => ignore))
    >>  _call_id: opt!(tlv!(0x9F, 0x82, 0x3E => ignore))
    >>  _output_called_number: opt!(tlv!(0x9F, 0x82, 0x3F => ignore))
    >>  _additional_caller_num: opt!(tlv!(0x9F, 0x82, 0x40 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_12 (rec: Record) <Record>,
    do_parse!(
        _setup_time_ms: opt!(tlv!(0x9F, 0x82, 0x42 => ignore))
    >>  _alerting_time_ms: opt!(tlv!(0x9F, 0x82, 0x43 => ignore))
    >>  _answer_time_ms: opt!(tlv!(0x9F, 0x82, 0x44 => ignore))
    >>  _release_time_ms: opt!(tlv!(0x9F, 0x82, 0x45 => ignore))
    >>  _overseas_flag: opt!(tlv!(0x9F, 0x82, 0x48 => ignore))
    >>  _service_attribute: opt!(tlv!(0x9F, 0x82, 0x49 => ignore))
    >>  (rec)
    )
);
