# Generated by default/object.tt
package Paws::FIS::Action;
  use Moose;
  has Description => (is => 'ro', isa => 'Str', request_name => 'description', traits => ['NameInRequest']);
  has Id => (is => 'ro', isa => 'Str', request_name => 'id', traits => ['NameInRequest']);
  has Parameters => (is => 'ro', isa => 'Paws::FIS::ActionParameterMap', request_name => 'parameters', traits => ['NameInRequest']);
  has Tags => (is => 'ro', isa => 'Paws::FIS::TagMap', request_name => 'tags', traits => ['NameInRequest']);
  has Targets => (is => 'ro', isa => 'Paws::FIS::ActionTargetMap', request_name => 'targets', traits => ['NameInRequest']);

1;

### main pod documentation begin ###

=head1 NAME

Paws::FIS::Action

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::FIS::Action object:

  $service_obj->Method(Att1 => { Description => $value, ..., Targets => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::FIS::Action object:

  $result = $service_obj->Method(...);
  $result->Att1->Description

=head1 DESCRIPTION

Describes an action. For more information, see AWS FIS actions
(https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html)
in the I<AWS Fault Injection Simulator User Guide>.

=head1 ATTRIBUTES


=head2 Description => Str

The description for the action.


=head2 Id => Str

The ID of the action.


=head2 Parameters => L<Paws::FIS::ActionParameterMap>

The action parameters, if applicable.


=head2 Tags => L<Paws::FIS::TagMap>

The tags for the action.


=head2 Targets => L<Paws::FIS::ActionTargetMap>

The supported targets for the action.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::FIS>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

