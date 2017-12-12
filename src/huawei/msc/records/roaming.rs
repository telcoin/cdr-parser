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
    >>  _served_imsi: tlv!(0x81 => ignore)
    >>  rec: field!(0x82 => address => rec.served_msisdn)
    >>  _calling_number: opt!(tlv!(0x83 => ignore))
    >>  _roaming_number: tlv!(0x84 => ignore)
    >>  _recording_entity: tlv!(0x85 => ignore)
    >>  _msc_incoming_route: opt!(tlv!(0xA6 => ignore))
    >>  _msc_outgoing_route: opt!(tlv!(0xA7 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_2 (rec: Record) <Record>,
    do_parse!(
        _basic_service: tlv!(0xA8 => ignore)
    >>  _transparency_indicator: opt!(tlv!(0x89 => ignore))
    >>  _change_of_service: opt!(tlv!(0xAA => ignore))
    >>  _suppl_services_used: opt!(tlv!(0xAB => ignore))
    >>  _seizure_time: opt!(tlv!(0x8C => ignore))
    >>  _answer_time: tlv!(0x8D => ignore)
    >>  _release_time: tlv!(0x8E => ignore)
    >>  _call_duration: tlv!(0x8F => ignore)
    >>  (rec)
    )
);

named_args!(subrec_2_3 (rec: Record) <Record>,
    do_parse!(
        _cause_for_term: tlv!(0x91 => ignore)
    >>  _diagnostics: tlv!(0xB2 => ignore)
    >>  _call_reference: tlv!(0x93 => ignore)
    >>  _sequence_number: opt!(tlv!(0x94 => ignore))
    >>  _record_extensions: opt!(tlv!(0xB5 => ignore))
    >>  _network_call_reference: tlv!(0x96 => ignore)
    >>  _msc_address: tlv!(0x97 => ignore)
    >>  _partial_record_type: opt!(tlv!(0x9E => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_4 (rec: Record) <Record>,
    do_parse!(
        _additional_chg_info: tlv!(0xBF, 0x81, 0x05 => ignore)
    >>  _ussd_call_back_flag: opt!(tlv!(0x9F, 0x81, 0x0A => ignore))
    >>  _charged_party: tlv!(0x9F, 0x81, 0x0D => ignore)
    >>  _original_called_number: opt!(tlv!(0x9F, 0x81, 0x0E => ignore))
    >>  _charge_area_code: opt!(tlv!(0x9F, 0x81, 0x11 => ignore))
    >>  _called_charge_area_code: opt!(tlv!(0x9F, 0x81, 0x12 => ignore))
    >>  _rate_indication: opt!(tlv!(0x9F, 0x81, 0x1F => ignore))
    >>  _msc_outgoing_circuit: opt!(tlv!(0x9F, 0x81, 0x26 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_5 (rec: Record) <Record>,
    do_parse!(
        _msc_incoming_circuit: opt!(tlv!(0x9F, 0x81, 0x27 => ignore))
    >>  _org_msc_id: opt!(tlv!(0x9F, 0x81, 0x28 => ignore))
    >>  _call_emlpp_priority: opt!(tlv!(0x9F, 0x81, 0x2A => ignore))
    >>  _default_call_handling: opt!(tlv!(0x9F, 0x81, 0x2B => ignore))
    >>  _free_format_data: opt!(tlv!(0x9F, 0x81, 0x2C => ignore))
    >>  _free_format_data_append: opt!(tlv!(0x9F, 0x81, 0x2D => ignore))
    >>  _ea_subscriber_info: opt!(tlv!(0x9F, 0x81, 0x2E => ignore))
    >>  _selected_cic: opt!(tlv!(0x9F, 0x81, 0x2F => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_6 (rec: Record) <Record>,
    do_parse!(
        _optimal_routing_flag: opt!(tlv!(0x9F, 0x81, 0x31 => ignore))
    >>  _caller_ported_flag: opt!(tlv!(0x9F, 0x81, 0x34 => ignore))
    >>  _subscriber_category: tlv!(0x9F, 0x81, 0x3E => ignore)
    >>  _cug_outgoing_access_indicator: opt!(tlv!(0x9F, 0x81, 0x43 => ignore))
    >>  _cug_interlock_code: opt!(tlv!(0x9F, 0x81, 0x44 => ignore))
    >>  _hot_billing_tag: opt!(tlv!(0x9F, 0x81, 0x48 => ignore))
    >>  _e_category: opt!(tlv!(0x9F, 0x81, 0x57 => ignore))
    >>  _gsm_scf_address: opt!(tlv!(0x9F, 0x81, 0x58 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_7 (rec: Record) <Record>,
    do_parse!(
        _service_key: opt!(tlv!(0x9F, 0x81, 0x59 => ignore))
    >>  _level_of_camel_service: opt!(tlv!(0x9F, 0x81, 0x5A => ignore))
    >>  _charge_pulse_num: opt!(tlv!(0x9F, 0x81, 0x5B => ignore))
    >>  _network_operator_id: opt!(tlv!(0x9F, 0x81, 0x5F => ignore))
    >>  _type_of_subscribers: opt!(tlv!(0x9F, 0x81, 0x60 => ignore))
    >>  _user_type: opt!(tlv!(0x9F, 0x81, 0x63 => ignore))
    >>  _record_number: opt!(tlv!(0x9F, 0x81, 0x68 => ignore))
    >>  _party_rel_cause: opt!(tlv!(0xBF, 0x81, 0x6C => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_8 (rec: Record) <Record>,
    do_parse!(
        _charge_level: opt!(tlv!(0x9F, 0x81, 0x6D => ignore))
    >>  _location_num: opt!(tlv!(0x9F, 0x81, 0x6E => ignore))
    >>  _location_number_nai: opt!(tlv!(0x9F, 0x81, 0x71 => ignore))
    >>  _translated_number: opt!(tlv!(0x9F, 0x81, 0x75 => ignore))
    >>  _icid_value: opt!(tlv!(0x9F, 0x81, 0x7B => ignore))
    >>  _termioi: opt!(tlv!(0x9F, 0x81, 0x7D => ignore))
    >>  _origioi: opt!(tlv!(0x9F, 0x81, 0x7E => ignore))
    >>  _called_ported_flag: opt!(tlv!(0x9F, 0x81, 0x7F => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_9 (rec: Record) <Record>,
    do_parse!(
        _location_routing_number: opt!(tlv!(0x9F, 0x82, 0x00 => ignore))
    >>  _routing_category: opt!(tlv!(0x9F, 0x82, 0x01 => ignore))
    >>  _intermediate_charging_indicator: opt!(tlv!(0x9F, 0x82, 0x02 => ignore))
    >>  _msc_outgoing_route_number: opt!(tlv!(0x9F, 0x82, 0x05 => ignore))
    >>  _msc_incoming_route_number: opt!(tlv!(0x9F, 0x82, 0x06 => ignore))
    >>  _ro_default_call_handling: opt!(tlv!(0x9F, 0x82, 0x07 => ignore))
    >>  _ro_link_failure_time: opt!(tlv!(0x9F, 0x82, 0x08 => ignore))
    >>  _last_succ_ccr_time: opt!(tlv!(0x9F, 0x82, 0x09 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_10 (rec: Record) <Record>,
    do_parse!(
        _drc_call_id: opt!(tlv!(0x9F, 0x82, 0x0A => ignore))
    >>  _drc_call_rn: opt!(tlv!(0x9F, 0x82, 0x0B => ignore))
    >>  _npdip_indicator: opt!(tlv!(0x9F, 0x82, 0x0C => ignore))
    >>  _ansi_routing_number: opt!(tlv!(0x9F, 0x82, 0x0D => ignore))
    >>  _lrn_source: opt!(tlv!(0x9F, 0x82, 0x0E => ignore))
    >>  _office_name: opt!(tlv!(0x9F, 0x82, 0x1D => ignore))
    >>  _npa_nxx: opt!(tlv!(0x9F, 0x82, 0x21 => ignore))
    >>  _global_call_reference: opt!(tlv!(0x9F, 0x82, 0x22 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_11 (rec: Record) <Record>,
    do_parse!(
        _called_ip_information: opt!(tlv!(0xBF, 0x82, 0x24 => ignore))
    >>  _cause_location: opt!(tlv!(0x9F, 0x82, 0x27 => ignore))
    >>  _presentation_and_screening_indicator: opt!(tlv!(0x9F, 0x82, 0x2B => ignore))
    >>  _group_id: opt!(tlv!(0x9F, 0x82, 0x2F => ignore))
    >>  _vpn_call_property: opt!(tlv!(0x9F, 0x82, 0x30 => ignore))
    >>  _subgroup_id: opt!(tlv!(0x9F, 0x82, 0x31 => ignore))
    >>  _number_portability_status: opt!(tlv!(0x9F, 0x82, 0x37 => ignore))
    >>  _anchor_flag: opt!(tlv!(0x9F, 0x82, 0x38 => ignore))
    >>  (rec)
    )
);

named_args!(subrec_2_12 (rec: Record) <Record>,
    do_parse!(
        _additional_routing_category: opt!(tlv!(0x9F, 0x82, 0x3D => ignore))
    >>  _additional_caller_num: opt!(tlv!(0x9F, 0x82, 0x40 => ignore))
    >>  _service_attribute: opt!(tlv!(0x9F, 0x82, 0x49 => ignore))
    >>  (rec)
    )
);
