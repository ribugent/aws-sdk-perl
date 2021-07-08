# Generated by default/object.tt
package Paws::Rekognition::ProtectiveEquipmentSummarizationAttributes;
  use Moose;
  has MinConfidence => (is => 'ro', isa => 'Num', required => 1);
  has RequiredEquipmentTypes => (is => 'ro', isa => 'ArrayRef[Str|Undef]', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::Rekognition::ProtectiveEquipmentSummarizationAttributes

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::Rekognition::ProtectiveEquipmentSummarizationAttributes object:

  $service_obj->Method(Att1 => { MinConfidence => $value, ..., RequiredEquipmentTypes => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::Rekognition::ProtectiveEquipmentSummarizationAttributes object:

  $result = $service_obj->Method(...);
  $result->Att1->MinConfidence

=head1 DESCRIPTION

Specifies summary attributes to return from a call to
DetectProtectiveEquipment. You can specify which types of PPE to
summarize. You can also specify a minimum confidence value for
detections. Summary information is returned in the C<Summary>
(ProtectiveEquipmentSummary) field of the response from
C<DetectProtectiveEquipment>. The summary includes which persons in an
image were detected wearing the requested types of person protective
equipment (PPE), which persons were detected as not wearing PPE, and
the persons in which a determination could not be made. For more
information, see ProtectiveEquipmentSummary.

=head1 ATTRIBUTES


=head2 B<REQUIRED> MinConfidence => Num

The minimum confidence level for which you want summary information.
The confidence level applies to person detection, body part detection,
equipment detection, and body part coverage. Amazon Rekognition doesn't
return summary information with a confidence than this specified value.
There isn't a default value.

Specify a C<MinConfidence> value that is between 50-100% as
C<DetectProtectiveEquipment> returns predictions only where the
detection confidence is between 50% - 100%. If you specify a value that
is less than 50%, the results are the same specifying a value of 50%.


=head2 B<REQUIRED> RequiredEquipmentTypes => ArrayRef[Str|Undef]

An array of personal protective equipment types for which you want
summary information. If a person is detected wearing a required
requipment type, the person's ID is added to the
C<PersonsWithRequiredEquipment> array field returned in
ProtectiveEquipmentSummary by C<DetectProtectiveEquipment>.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::Rekognition>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

