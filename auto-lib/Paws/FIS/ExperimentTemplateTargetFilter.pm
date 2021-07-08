# Generated by default/object.tt
package Paws::FIS::ExperimentTemplateTargetFilter;
  use Moose;
  has Path => (is => 'ro', isa => 'Str', request_name => 'path', traits => ['NameInRequest']);
  has Values => (is => 'ro', isa => 'ArrayRef[Str|Undef]', request_name => 'values', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::FIS::ExperimentTemplateTargetFilter

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::FIS::ExperimentTemplateTargetFilter object:

  $service_obj->Method(Att1 => { Path => $value, ..., Values => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::FIS::ExperimentTemplateTargetFilter object:

  $result = $service_obj->Method(...);
  $result->Att1->Path

=head1 DESCRIPTION

Describes a filter used for the target resources in an experiment
template.

=head1 ATTRIBUTES


=head2 Path => Str

The attribute path for the filter.


=head2 Values => ArrayRef[Str|Undef]

The attribute values for the filter.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::FIS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

